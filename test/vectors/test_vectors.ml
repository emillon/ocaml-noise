open OUnit2
open Noise.Util

module KU = struct
  type 'k t =
    | Known of 'k
    | Unknown of string

  let unwrap what x f =
    match x with
    | Known y -> f y
    | Unknown s ->
      Printf.ksprintf
        (fun e -> Error e)
        "Unknown %s: %s"
        what
        s
end

module type OF_STRING = sig
  type t
  val of_string : string -> (t, string) result
end

module Make_KU(M:OF_STRING) = struct
  type t = M.t KU.t

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    [%of_yojson: string] json >|= fun s ->
    match M.of_string s with
    | Ok x -> KU.Known x
    | Error _ -> Unknown s
end

module Pattern = Make_KU(Noise.Pattern)
module Dh = Make_KU(Noise.Dh)
module Cipher = Make_KU(Noise.Cipher)
module Hash = Make_KU(Noise.Hash)

type message =
  { ciphertext : Test_helpers.Hex_string.t
  ; payload : Test_helpers.Hex_string.t
  }
[@@deriving of_yojson]

module Public_key = struct
  type t = Noise.Public_key.t

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    [%of_yojson: Test_helpers.Hex_string.t] json >|= Noise.Public_key.of_bytes
end

module Private_key = struct
  type t = Noise.Private_key.t

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    [%of_yojson: Test_helpers.Hex_string.t] json >|= Noise.Private_key.of_bytes
end

type test_vector =
  { name : string
  ; pattern : Pattern.t
  ; dh : Dh.t
  ; cipher: Cipher.t
  ; hash : Hash.t
  ; init_prologue : string
  ; init_ephemeral : Private_key.t
  ; init_remote_static : Public_key.t option [@default None]
  ; resp_prologue : Test_helpers.Hex_string.t
  ; resp_static : Private_key.t option [@default None]
  ; messages : message list
  ; handshake_hash : Test_helpers.Hex_string.t
  ; init_psk : string option [@default None]
  ; init_static : Private_key.t option [@default None]
  ; resp_ephemeral : Private_key.t option [@default None]
  ; resp_psk : string option [@default None]
  ; resp_remote_static : Public_key.t option [@default None]
  }
[@@deriving of_yojson]

type test_vector_file =
  { vectors : test_vector list
  }
[@@deriving of_yojson]

let params vector =
  KU.unwrap "pattern" vector.pattern @@ fun pattern ->
  KU.unwrap "DH" vector.dh @@ fun dh ->
  KU.unwrap "cipher" vector.cipher @@ fun cipher ->
  KU.unwrap "hash" vector.hash @@ fun hash ->
  Ok (pattern, dh, cipher, hash)

let get_exn msg = function
  | Some x -> x
  | None -> Printf.ksprintf invalid_arg "get_exn: %s" msg

let get_result_exn msg = function
  | Ok x -> x
  | Error e -> Printf.ksprintf invalid_arg "get_result_exn: %s (%s)" msg e

let is_some = function
  | Some _ -> true
  | None -> false

let check_one_way_transport_message ~ctxt initiator responder message n =
  let (new_resp, recovered_plaintext) =
    get_result_exn
      "transport message, responder"
      ( Noise.State.One_way_transport.receive
          responder
          message.ciphertext
      )
  in
  assert_equal
    ~ctxt
    ~cmp:[%eq: Test_helpers.Hex_string.t]
    ~printer:[%show: Test_helpers.Hex_string.t]
    ~msg:(Printf.sprintf "Transport message #%d decryption" n)
    message.payload
    recovered_plaintext;
  let (new_init, generated_ciphertext) =
    get_result_exn "transport 1, sender"
      ( Noise.State.One_way_transport.send
          initiator
          message.payload
      )
  in
  assert_equal
    ~ctxt
    ~cmp:[%eq: Test_helpers.Hex_string.t]
    ~printer:[%show: Test_helpers.Hex_string.t]
    ~msg:(Printf.sprintf "Transport message #%d encryption" n)
    message.ciphertext
    generated_ciphertext;
  (new_init, new_resp)

let concat_some a b =
  match a, b with
  | None, None -> []
  | Some sa, None -> [sa]
  | None, Some sb -> [sb]
  | Some sa, Some sb -> [sa; sb]

let make_responder_from_vector pattern dh cipher hash vector =
  let e = vector.resp_ephemeral in
  let s = vector.resp_static in
  let static_pub = vector.init_remote_static in
  let rs = vector.resp_remote_static in
  Noise.State.make
    ~name:vector.name
    ~pattern
    ~is_initiator:false
    ~s
    ~rs
    ~e
    ~dh
    ~cipher
    ~hash
  |> Noise.Protocol.initialize
    ~prologue:vector.resp_prologue
    ~public_keys:(concat_some rs static_pub)

let make_initiator_from_vector pattern dh cipher hash vector =
  let rs = vector.init_remote_static in
  let e = vector.init_ephemeral in
  let s = vector.init_static in
  let s_pub = vector.resp_remote_static in
  Noise.State.make
    ~name:vector.name
    ~is_initiator:true
    ~pattern
    ~s
    ~rs
    ~e:(Some e)
    ~dh
    ~cipher
    ~hash
  |> Noise.Protocol.initialize
    ~prologue:vector.resp_prologue
    ~public_keys:(concat_some s_pub rs)

let hd_tl_exn = function
  | hd::tl -> (hd, tl)
  | [] -> assert false

let build_test_case vector =
  vector.name >:: fun ctxt ->
    skip_if
      (is_some vector.init_psk)
      "PSK is not supported";
    match params vector with
    | Error e ->
      skip_if true e
    | Ok (pattern, dh, cipher, hash) ->
      let responder = make_responder_from_vector pattern dh cipher hash vector in
      let first_msg, transport_messages = hd_tl_exn vector.messages in
      let initiator = make_initiator_from_vector pattern dh cipher hash vector in

      let initiator_post_handshake =
        Noise.Protocol.write_message
          initiator
          first_msg.payload
        >>= fun (n1, _) ->
        Ok n1
      in
      let initiator_post_handshake =
        get_result_exn "initiator_post_handshake" initiator_post_handshake
      in
      let initiator_hash =
        get_exn "init hash" @@
        Noise.State.handshake_hash initiator_post_handshake
      in

      let responder_post_handshake =
        Noise.Protocol.read_message responder first_msg.ciphertext
        >>= fun (n1, (_:Cstruct.t)) ->
        Ok n1
      in
      let responder_post_handshake =
        get_result_exn "responder_post_handshake" responder_post_handshake
      in
      let responder_hash =
        get_exn "resp hash" @@
        Noise.State.handshake_hash responder_post_handshake
      in

      assert_equal
        ~ctxt
        ~cmp:[%eq: Test_helpers.Hex_string.t]
        ~printer:[%show: Test_helpers.Hex_string.t]
        ~msg:"Handshake hashes should match"
        initiator_hash
        responder_hash;
      assert_equal
        ~cmp:[%eq: Test_helpers.Hex_string.t]
        ~printer:[%show: Test_helpers.Hex_string.t]
        ~msg:"Handshake hash should match the vector"
        vector.handshake_hash
        initiator_hash;

      let _ : Noise.State.t * Noise.State.t * int =
        List.fold_left
          (fun (init, resp, i) message ->
             let (new_init, new_resp) =
               check_one_way_transport_message ~ctxt init resp message i
             in
             (new_init, new_resp, i+1)
          )
          ( initiator_post_handshake
          , responder_post_handshake
          , 1
          )
          transport_messages
      in
      ()

let run path =
  let json = Yojson.Safe.from_file path in
  match test_vector_file_of_yojson json with
  | Ok { vectors } -> path >::: List.map build_test_case vectors
  | Error e -> failwith e

let suite =
  "noise-c test vectors" >:::
  [ run "noise-c-basic.txt"
  ]

let () =
  run_test_tt_main suite

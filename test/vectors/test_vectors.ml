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

let get_result_exn msg = function
  | Ok x -> x
  | Error e -> Printf.ksprintf invalid_arg "get_result_exn: %s (%s)" msg e

let is_some = function
  | Some _ -> true
  | None -> false

let check_transport_message ~ctxt initiator responder message n =
  let (new_resp, recovered_plaintext) =
    get_result_exn
      "transport message, responder"
      ( Noise.State.receive_transport
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
      ( Noise.State.send_transport
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

let handshake_len =
  let open Noise.Pattern in
  function
  | N
  | K
  | X
    ->
    1
  | NN
  | NX
  | IN
  | IX
    ->
    2
  | XN
  | XX
    ->
    3

let post_handshake pattern init0 resp0 msgs =
  match handshake_len pattern, msgs with
  | 1, msg1::msgs ->
    Noise.Protocol.write_message init0 msg1.payload >>= fun (init1, _) ->
    Noise.Protocol.read_message resp0 msg1.ciphertext >>= fun (resp1, _) ->
    Ok (init1, resp1, msgs)
  | 2, msg1::msg2::msgs ->
    Noise.Protocol.write_message init0 msg1.payload >>= fun (init1, _) ->
    Noise.Protocol.read_message resp0 msg1.ciphertext >>= fun (resp1, _) ->
    Noise.Protocol.write_message resp1 msg2.payload >>= fun (resp2, _) ->
    Noise.Protocol.read_message init1 msg2.ciphertext >>= fun (init2, _) ->
    Ok (init2, resp2, msgs)
  | 3, msg1::msg2::msg3::msgs ->
    Noise.Protocol.write_message init0 msg1.payload >>= fun (init1, _) ->
    Noise.Protocol.read_message resp0 msg1.ciphertext >>= fun (resp1, _) ->
    Noise.Protocol.write_message resp1 msg2.payload >>= fun (resp2, _) ->
    Noise.Protocol.read_message init1 msg2.ciphertext >>= fun (init2, _) ->
    Noise.Protocol.write_message init2 msg3.payload >>= fun (init3, _) ->
    Noise.Protocol.read_message resp2 msg3.ciphertext >>= fun (resp3, _) ->
    Ok (resp3, init3, msgs)
  | _ ->
    Error "Wrong number of messages"

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
      let initiator = make_initiator_from_vector pattern dh cipher hash vector in

      let (initiator_post_handshake, responder_post_handshake, transport_messages) =
        get_result_exn "post_handshake" @@
        post_handshake pattern initiator responder vector.messages
      in
      let initiator_hash =
        Noise.State.handshake_hash initiator_post_handshake
      in
      let responder_hash =
        Noise.State.handshake_hash responder_post_handshake
      in

      assert_equal
        ~ctxt
        ~cmp:[%eq: Test_helpers.Hex_string.t option]
        ~printer:[%show: Test_helpers.Hex_string.t option]
        ~msg:"Handshake hashes should match"
        initiator_hash
        responder_hash;
      assert_equal
        ~cmp:[%eq: Test_helpers.Hex_string.t option]
        ~printer:[%show: Test_helpers.Hex_string.t option]
        ~msg:"Handshake hash should match the vector"
        (Some vector.handshake_hash)
        initiator_hash;

      let flip a b =
        match Noise.Pattern.transport pattern with
        | One_way ->
          (a, b)
        | Two_way ->
          (b, a)
      in
      let _ : Noise.State.t * Noise.State.t * int =
        List.fold_left
          (fun (init, resp, i) message ->
             let (new_init, new_resp) =
               check_transport_message ~ctxt init resp message i
             in
             let (new_init1, new_resp1) = flip new_init new_resp in
             (new_init1, new_resp1, i+1)
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

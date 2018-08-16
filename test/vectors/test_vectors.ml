open OUnit2

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

let init_public_data n0 ~prologue ~pre_public_keys =
  List.fold_left
    Noise.State.mix_hash
    n0
    (prologue::List.map Noise.Public_key.bytes pre_public_keys)

let (>>=) x f =
  match x with
  | Ok x -> f x
  | Error _ as e -> e

let is_some = function
  | Some _ -> true
  | None -> false

let resp_handler_e n0 msg0 =
  let (re, msg1) = Noise.State.split_dh n0 msg0 in
  Noise.State.set_re n0 re >>= fun n1 ->
  let n2 = Noise.State.mix_hash n1 (Noise.Public_key.bytes re) in
  Ok (n2, msg1)

let responder_handle_es s =
  Noise.State.mix_dh_key
    s
    ~priv:(get_exn "s" @@ Noise.State.s s)
    ~pub:(get_exn "re" @@ Noise.State.re s)

let handle_ss s =
  Noise.State.mix_dh_key
    s
    ~priv:(get_exn "s" @@ Noise.State.s s)
    ~pub:(get_exn "rs" @@ Noise.State.rs s)

type resp_handler =
  Noise.State.t ->
  Cstruct.t ->
  (Noise.State.t * Cstruct.t, string) result

let resp_handler_es : resp_handler =
  fun s msg ->
    let new_s = responder_handle_es s in
    Ok (new_s, msg)

let resp_handler_ss : resp_handler =
  fun s msg ->
    let new_s = handle_ss s in
    Ok (new_s, msg)

let resp_handler_payload : resp_handler =
  fun s msg ->
    Noise.State.decrypt_and_hash s msg >>= fun (new_s, new_msg) ->
    Ok
      ( Noise.State.One_way_transport.setup new_s
      , new_msg
      )

let resp_handler_s : resp_handler =
  fun s0 msg ->
    let (temp, new_msg) = Noise.State.split_dh s0 msg in
    Noise.State.decrypt_and_hash s0 (Noise.Public_key.bytes temp) >>= fun (s1, plaintext) ->
    Noise.State.set_rs s1 (Noise.Public_key.of_bytes plaintext) >>= fun s2 ->
    Ok (s2, new_msg)

let rec compose_resp_handlers : resp_handler list -> resp_handler =
  fun handlers s msg ->
    match handlers with
    | hdl::hdls ->
      hdl s msg >>= fun (next_s, next_msg) ->
      compose_resp_handlers hdls next_s next_msg
    | [] -> Ok (s, msg)

let init_handler_e n0 =
  let epub = get_exn "epub" @@ Noise.State.e_pub n0 in
  let n1 = Noise.State.mix_hash n0 (Noise.Public_key.bytes epub) in
  Ok (n1, Noise.Public_key.bytes epub)

let init_return x = Ok (x, Cstruct.empty)

let init_handler_es n =
  Noise.State.mix_dh_key
    n
    ~priv:(get_exn "e" @@ Noise.State.e n)
    ~pub:(get_exn "rs" @@ Noise.State.rs n)
  |> init_return

type init_handler =
  Noise.State.t ->
  (Noise.State.t * Cstruct.t, string) result

let init_handler_payload payload : init_handler =
  fun n0 ->
    Noise.State.encrypt_and_hash n0 payload >>= fun (n1, msg1) ->
    let n2 = Noise.State.One_way_transport.setup n1 in
    Ok (n2, msg1)

let init_handler_ss : init_handler =
  fun n ->
    init_return @@ handle_ss n

let init_handler_s : init_handler =
  fun s ->
    let s_pub = get_exn "s_pub" @@ Noise.State.s_pub s in
    let plaintext = Noise.Public_key.bytes s_pub in
    Noise.State.encrypt_and_hash s plaintext

let compose_init_handlers : init_handler list -> init_handler =
  let rec go msgs s = function
    | [] -> Ok (s, Cstruct.concat (List.rev msgs))
    | hdl::hdls ->
      hdl s >>= fun (new_s, new_msg) ->
      go (new_msg::msgs) new_s hdls
  in
  fun handlers state ->
    go [] state handlers

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

let init_handlers pattern payload =
  match pattern with
  | Noise.Pattern.N ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_payload payload
    ]
  | Noise.Pattern.K ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_ss
    ; init_handler_payload payload
    ]
  | Noise.Pattern.X ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_s
    ; init_handler_ss
    ; init_handler_payload payload
    ]

let initiator_handshake pattern state payload =
  compose_init_handlers (init_handlers pattern payload) state

let responder_handlers = function
  | Noise.Pattern.N ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_payload
    ]
  | Noise.Pattern.K ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_ss
    ; resp_handler_payload
    ]
  | Noise.Pattern.X ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_s
    ; resp_handler_ss
    ; resp_handler_payload
    ]

let responder_handshake pattern =
  compose_resp_handlers (responder_handlers pattern)

let concat_some a b =
  match a, b with
  | None, None -> []
  | Some sa, None -> [sa]
  | None, Some sb -> [sb]
  | Some sa, Some sb -> [sa; sb]

let make_responder_from_vector dh cipher hash vector =
  let e = vector.resp_ephemeral in
  let s = vector.resp_static in
  let static_pub = vector.init_remote_static in
  let rs = vector.resp_remote_static in
  Noise.State.make
    ~name:vector.name
    ~s
    ~rs
    ~e
    ~dh
    ~cipher
    ~hash
  |> init_public_data
    ~prologue:vector.resp_prologue
    ~pre_public_keys:(concat_some rs static_pub)

let make_initiator_from_vector dh cipher hash vector =
  let rs = vector.init_remote_static in
  let e = vector.init_ephemeral in
  let s = vector.init_static in
  let s_pub = vector.resp_remote_static in
  Noise.State.make
    ~name:vector.name
    ~s
    ~rs
    ~e:(Some e)
    ~dh
    ~cipher
    ~hash
  |> init_public_data
    ~prologue:vector.resp_prologue
    ~pre_public_keys:(concat_some s_pub rs)

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
      let responder = make_responder_from_vector dh cipher hash vector in
      let first_msg, transport_messages = hd_tl_exn vector.messages in
      let initiator = make_initiator_from_vector dh cipher hash vector in

      let initiator_post_handshake =
        initiator_handshake
          pattern
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
        responder_handshake pattern responder first_msg.ciphertext
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

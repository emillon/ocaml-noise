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

type params =
  { pattern : Noise.Pattern.t
  ; dh : Noise.Dh.t
  ; cipher : Noise.Cipher.t
  ; hash : Noise.Hash.t
  }

type test_vector_file =
  { vectors : test_vector list
  }
[@@deriving of_yojson]

let params (vector : test_vector) =
  KU.unwrap "pattern" vector.pattern @@ fun pattern ->
  KU.unwrap "DH" vector.dh @@ fun dh ->
  KU.unwrap "cipher" vector.cipher @@ fun cipher ->
  KU.unwrap "hash" vector.hash @@ fun hash ->
  Ok { pattern; dh; cipher; hash }

let get_exn msg = function
  | Some x -> x
  | None -> Printf.ksprintf invalid_arg "get_exn: %s" msg

let get_result_exn msg = function
  | Ok x -> x
  | Error e -> Printf.ksprintf invalid_arg "get_result_exn: %s (%s)" msg e

type state =
  { re : Public_key.t option
  ; e : Private_key.t option
  ; rs : Public_key.t option
  ; s : Private_key.t option
  ; symmetric_state : Noise.Symmetric_state.t
  ; params : params
  ; cipher_state : Noise.Cipher_state.t
  ; transport : Noise.Cipher_state.t option
  }

let e_pub state =
  Noise.Dh_25519.public_key @@ get_exn "e_pub" state.e

let s_pub state =
  Noise.Dh_25519.public_key @@ get_exn "s_pub" state.s

let mix_hash n data =
  { n with
    symmetric_state =
      Noise.Symmetric_state.mix_hash
        n.symmetric_state
        data
  }

let init_public_data n0 ~prologue ~pre_public_keys =
  List.fold_left
    mix_hash
    n0
    (prologue::List.map Noise.Public_key.bytes pre_public_keys)

let prep_h name hash =
  let buf_name = Cstruct.of_string name in
  let hashlen = Noise.Hash.len hash in
  let name_len = Cstruct.len buf_name in
  if name_len <= hashlen then
    let buf = Cstruct.create hashlen in
    Cstruct.blit buf_name 0 buf 0 name_len;
    buf
  else
    Noise.Hash.hash hash buf_name

let split_dh ~extra16 params msg =
  let dh_len = Noise.Dh.len params.dh in
  let len =
    if extra16 then
      dh_len + 16
    else
      dh_len
  in
  let (a, b) = Cstruct.split msg len in
  (Noise.Public_key.of_bytes a, b)

let initial_set_re n k =
  match n.re with
  | None -> { n with re = Some k }
  | Some _ -> failwith "initial_set_re"

let initial_set_rs n k =
  match n.rs with
  | None -> { n with rs = Some k }
  | Some _ -> failwith "initial_set_rs"

let mix_key n0 input =
  let (new_symmetric_state, new_key) =
    Noise.Symmetric_state.mix_key
      n0.symmetric_state
      input
  in
  { n0 with
      cipher_state = Noise.Cipher_state.create new_key
    ; symmetric_state = new_symmetric_state
  }

let (>>=) x f =
  match x with
  | Ok x -> f x
  | Error _ as e -> e

let decrypt_with_ad_cs cipher_state ~ad cipher =
  Noise.Cipher_state.with_ cipher_state
    (Noise.Cipher.decrypt_with_ad cipher ~ad)

let decrypt_with_ad n0 ciphertext_and_tag =
  decrypt_with_ad_cs
    n0.cipher_state
    ~ad:(Noise.Symmetric_state.h n0.symmetric_state)
    n0.params.cipher
    ciphertext_and_tag
  >>= fun (new_cs, plaintext) ->
  let n1 = {n0 with cipher_state = new_cs} in
  Ok (n1, plaintext)

let is_some = function
  | Some _ -> true
  | None -> false

let get_handshake n =
  assert (is_some n.transport);
  Noise.Symmetric_state.h n.symmetric_state

let decrypt_and_hash n0 ciphertext =
  decrypt_with_ad n0 ciphertext >>= fun (n1, plaintext) ->
  let n2 = mix_hash n1 ciphertext in
  Ok (n2, plaintext)

let responder_handle_e n0 msg0 =
  let (re, msg1) = split_dh ~extra16:false n0.params msg0 in
  let n1 = initial_set_re n0 re in
  let n2 = mix_hash n1 (Noise.Public_key.bytes re) in
  (n2, msg1)

let responder_handle_es n =
  Noise.Dh.key_exchange
    n.params.dh
    ~priv:(get_exn "s" n.s)
    ~pub:(get_exn "re" n.re)
  |>
  mix_key n

let handle_ss n =
  Noise.Dh.key_exchange
    n.params.dh
    ~priv:(get_exn "s" n.s)
    ~pub:(get_exn "rs" n.rs)
  |>
  mix_key n

let setup_transport_one_way s =
  { s with
    transport =
      Some
        (Noise.Symmetric_state.split_one_way s.symmetric_state)
  }

type resp_handler =
  state -> Cstruct.t -> (state * Cstruct.t, string) result

let resp_handler_e : resp_handler =
  fun s msg ->
    Ok (responder_handle_e s msg)

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
    decrypt_and_hash s msg >>= fun (new_s, new_msg) ->
    Ok
      ( setup_transport_one_way new_s
      , new_msg
      )

let resp_handler_s : resp_handler =
  fun s0 msg ->
    let (temp, new_msg) =
      split_dh
        ~extra16:(Noise.Cipher_state.has_key s0.cipher_state)
        s0.params msg
    in
    decrypt_and_hash s0 (Noise.Public_key.bytes temp) >>= fun (s1, plaintext) ->
    Ok (initial_set_rs s1 (Noise.Public_key.of_bytes plaintext), new_msg)

let rec compose_resp_handlers : resp_handler list -> resp_handler =
  fun handlers s msg ->
    match handlers with
    | hdl::hdls ->
      hdl s msg >>= fun (next_s, next_msg) ->
      compose_resp_handlers hdls next_s next_msg
    | [] -> Ok (s, msg)

let make_state ~h ~params ~s ~rs ~e =
  let symmetric_state =
    Noise.Symmetric_state.create
      params.hash
      params.dh
      h
  in
  { re = None
  ; e
  ; s
  ; rs
  ; params
  ; symmetric_state
  ; cipher_state = Noise.Cipher_state.empty
  ; transport = None
  }

let init_handler_e n0 =
  let epub = e_pub n0 in
  let n1 = mix_hash n0 (Noise.Public_key.bytes epub) in
  Ok (n1, Noise.Public_key.bytes epub)

let init_return x = Ok (x, Cstruct.empty)

let init_handler_es n =
  Noise.Dh.key_exchange
    n.params.dh
    ~priv:(get_exn "e" n.e)
    ~pub:(get_exn "rs" n.rs)
  |> mix_key n
  |> init_return

let encrypt_with_ad_cs cipher_state ~ad cipher =
  Noise.Cipher_state.with_ cipher_state
    (Noise.Cipher.encrypt_with_ad cipher ~ad)

let encrypt_with_ad n0 plaintext =
  encrypt_with_ad_cs
    n0.cipher_state
    ~ad:(Noise.Symmetric_state.h n0.symmetric_state)
    n0.params.cipher
    plaintext
  >>= fun (new_cs, ciphertext) ->
  let n1 = {n0 with cipher_state = new_cs } in
  Ok (n1, ciphertext)

let encrypt_and_hash n0 payload =
  encrypt_with_ad n0 payload >>= fun (n1, ciphertext) ->
  let n2 = mix_hash n1 ciphertext in
  Ok (n2, ciphertext)

type init_handler = state -> (state * Cstruct.t, string) result

let init_handler_payload payload : init_handler =
  fun n0 ->
    encrypt_and_hash n0 payload >>= fun (n1, msg1) ->
    let n2 = setup_transport_one_way n1 in
    Ok (n2, msg1)

let init_handler_ss : init_handler =
  fun n ->
    init_return @@ handle_ss n

let init_handler_s : init_handler =
  fun s ->
    let s_pub = s_pub s in
    let plaintext = Noise.Public_key.bytes s_pub in
    encrypt_and_hash s plaintext

let compose_init_handlers : init_handler list -> init_handler =
  let rec go msgs s = function
    | [] -> Ok (s, Cstruct.concat (List.rev msgs))
    | hdl::hdls ->
      hdl s >>= fun (new_s, new_msg) ->
      go (new_msg::msgs) new_s hdls
  in
  fun handlers state ->
    go [] state handlers

let with_transport_one_way n0 k =
  match n0.transport with
  | Some cipher_state ->
    k cipher_state >>= fun (new_cs, result) ->
    let n1 =
      { n0 with
        transport = Some new_cs
      }
    in
    Ok (n1, result)
  | None ->
    Error "Handshake not finished"

let receive_transport_one_way n0 ciphertext =
  with_transport_one_way n0 @@ fun cipher_state ->
  decrypt_with_ad_cs
    cipher_state
    ~ad:Cstruct.empty
    n0.params.cipher
    ciphertext

let send_transport_one_way n0 plaintext =
  with_transport_one_way n0 @@ fun cipher_state ->
  encrypt_with_ad_cs
    cipher_state
    ~ad:Cstruct.empty
    n0.params.cipher
    plaintext

let check_one_way_transport_message ~ctxt initiator responder message n =
  let (new_resp, recovered_plaintext) =
    get_result_exn
      "transport message, responder"
      ( receive_transport_one_way
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
      ( send_transport_one_way
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

let make_responder_from_vector params vector =
  let h = prep_h vector.name params.hash in
  let e = vector.resp_ephemeral in
  let s = vector.resp_static in
  let static_pub = vector.init_remote_static in
  let rs = vector.resp_remote_static in
  make_state
    ~s
    ~rs
    ~e
    ~params
    ~h
  |> init_public_data
    ~prologue:vector.resp_prologue
    ~pre_public_keys:(concat_some rs static_pub)

let make_initiator_from_vector params vector =
  let h = prep_h vector.name params.hash in
  let rs = vector.init_remote_static in
  let e = vector.init_ephemeral in
  let s = vector.init_static in
  let s_pub = vector.resp_remote_static in
  make_state
    ~h
    ~s
    ~rs
    ~e:(Some e)
    ~params
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
    | Ok params ->
      let responder = make_responder_from_vector params vector in
      let first_msg, transport_messages = hd_tl_exn vector.messages in
      let initiator = make_initiator_from_vector params vector in

      let initiator_post_handshake =
        initiator_handshake
          params.pattern
          initiator
          first_msg.payload
        >>= fun (n1, _) ->
        Ok n1
      in
      let initiator_post_handshake =
        get_result_exn "initiator_post_handshake" initiator_post_handshake
      in
      let initiator_post_hs_cipher = initiator_post_handshake.cipher_state in
      let initiator_hash = get_handshake initiator_post_handshake in

      let responder_post_handshake =
        responder_handshake params.pattern responder first_msg.ciphertext
        >>= fun (n1, (_:Cstruct.t)) ->
        Ok n1
      in
      let responder_post_handshake =
        get_result_exn "responder_post_handshake" responder_post_handshake
      in
      let responder_post_hs_cipher = responder_post_handshake.cipher_state in
      let responder_hash = get_handshake responder_post_handshake in

      assert_equal
        ~ctxt
        ~cmp:[%eq: Noise.Cipher_state.t]
        ~printer:[%show: Noise.Cipher_state.t]
        ~msg:"Final states should be equal"
        initiator_post_hs_cipher
        responder_post_hs_cipher;
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

      let _ : state * state * int =
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

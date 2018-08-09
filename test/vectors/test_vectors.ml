open OUnit2


(*

{
  "name": "Noise_N_25519_AESGCM_SHA256",
  "pattern": "N",
  "dh": "25519",
  "cipher": "AESGCM",
  "hash": "SHA256",
  "init_prologue": "50726f6c6f677565313233",
  "init_ephemeral": "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  "init_remote_static": "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
  "resp_prologue": "50726f6c6f677565313233",
  "resp_static": "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  "messages": [
    {
      "payload": "4c756477696720766f6e204d69736573",
      "ciphertext": "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944579bcbff029d662564fea10d563023315b0169ccc7b59ce9c45807238591a248"
    },
    {
      "payload": "4d757272617920526f746862617264",
      "ciphertext": "ece41448702945ed9004d6d83e98f24eadf3ba377084829bcc1508f37ebf52"
    },
    {
      "payload": "462e20412e20486179656b",
      "ciphertext": "c23a5f1fbd44cc5ccf9f5173dbdc269cd62e4d3da636f9f7d86da8"
    },
    {
      "payload": "4361726c204d656e676572",
      "ciphertext": "3f75522cb7de92072d28d7f2aed8eaec0a16e4a2f72cfc533656c8"
    },
    {
      "payload": "4a65616e2d426170746973746520536179",
      "ciphertext": "a6d69707c4915cb7322a678c01e212005f11a948e5fb22506aa81943793c6c289f"
    },
    {
      "payload": "457567656e2042f6686d20766f6e2042617765726b",
      "ciphertext": "6d1a4b057667d4b8ae113f219c53b57c4c3574b259701f0e0e77d762c1188b04fa76d255f4"
    }
  ],
  "handshake_hash": "e0ada57e5ed2a075a4654cd6041870c33a68ae3c81a365dfea019a89540b2fbd"
}

   *)

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
  ; init_static : string option [@default None]
  ; resp_ephemeral : string option [@default None]
  ; resp_psk : string option [@default None]
  ; resp_remote_static : string option [@default None]
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
  | Error _ -> Printf.ksprintf invalid_arg "get_result_exn: %s" msg

type state =
  { re : Public_key.t option
  ; e : Private_key.t option
  ; rs : Public_key.t option
  ; s : Private_key.t option
  ; ck : Cstruct.t
  ; h : Cstruct.t
  ; handshake_done : bool
  ; params : params
  ; cipher_state : Noise.Cipher_state.t
  }

let mix_hash n data =
  let new_h =
    Noise.Hash.hash n.params.hash (Cstruct.concat [n.h; data])
  in
  { n with h = new_h }

let init_public_data n0 ~prologue ~s_pub =
  let n1 = mix_hash n0 prologue in
  let n2 = mix_hash n1 (Noise.Public_key.bytes s_pub) in
  n2

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

let make_responder ~s ~h ~params =
  { re = None
  ; e = None
  ; s = Some s
  ; rs = None
  ; ck = h
  ; h
  ; handshake_done = false
  ; params
  ; cipher_state = Noise.Cipher_state.Empty
  }

let split_dh params msg =
  let dh_len = Noise.Dh.len params.dh in
  let (a, b) = Cstruct.split msg dh_len in
  (Noise.Public_key.of_bytes a, b)

let initial_set_re n k =
  match n.re with
  | None -> { n with re = Some k }
  | Some _ -> failwith "initial_set_re"

let initial_set_e n k =
  match n.e with
  | None -> { n with e = Some k }
  | Some _ -> failwith "initial_set_e"

let hkdf2 params ck input =
  let hash = params.hash in
  let hashlen = Noise.Hash.len hash in
  assert (Cstruct.len ck = hashlen);
  let ikm_length = Cstruct.len input in
  let dh_len = Noise.Dh.len params.dh in
  assert (
    List.mem ikm_length [0; 32; dh_len]
  );
  Noise.Hkdf.hkdf2
    ~hmac:(Noise.Hash.hmac hash)
    ~salt:ck
    ~ikm:input

let initialize_key n key =
  { n with
    cipher_state = Noise.Cipher_state.create key
  }

let set_ck n ck =
  { n with ck }

let mix_key n0 input =
  let ck0 = n0.ck in
  let (ck1, temp_k) = hkdf2 n0.params ck0 input in
  let n1 = set_ck n0 ck1 in
  let truncated_temp_k =
    if Noise.Hash.len n1.params.hash = 64 then
      Cstruct.sub temp_k 0 32
    else
      temp_k
  in
  initialize_key n1 (Noise.Private_key.of_bytes truncated_temp_k)

let incr_nonce n =
  { n with
    cipher_state = Noise.Cipher_state.incr_nonce n.cipher_state
  }

let (>>=) x f =
  match x with
  | Ok x -> f x
  | Error _ as e -> e

let decrypt_with_ad n0 ciphertext_and_tag =
  match n0.cipher_state with
  | Empty -> Ok (n0, ciphertext_and_tag)
  | Depleted -> Error "Nonce depleted"
  | Ready {key; nonce} ->
    let decrypt_result =
      Noise.Cipher.decrypt_with_ad
        n0.params.cipher
        ~key
        ~nonce
        ~ad:n0.h
        ciphertext_and_tag
    in
    decrypt_result >>= fun plaintext ->
    let n1 = incr_nonce n0 in
    Ok (n1, plaintext)

let get_handshake n =
  assert n.handshake_done;
  n.h

let decrypt_and_hash n0 ciphertext =
  decrypt_with_ad n0 ciphertext >>= fun (n1, plaintext) ->
  let n2 = mix_hash n1 ciphertext in
  Ok (n2, plaintext)

let responder_handle_e n0 msg0 =
  let (re, msg1) = split_dh n0.params msg0 in
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

let responder_handle_e_es n0 msg0 =
  let (n1, msg1) = responder_handle_e n0 msg0 in
  let n2 = responder_handle_es n1 in
  decrypt_and_hash n2 msg1 >>= fun (n3, payload) ->
  Ok (n3, payload)

let make_init ~h ~rs ~params =
  { h
  ; re = None
  ; e = None
  ; s = None
  ; rs = Some rs
  ; ck = h
  ; handshake_done = false
  ; params
  ; cipher_state = Noise.Cipher_state.Empty
  }

let init_handle_e n0 epub epriv =
  let n1 = initial_set_e n0 epriv in
  let n2 = mix_hash n1 (Noise.Public_key.bytes epub) in
  (n2, Noise.Public_key.bytes epub)

let init_handle_es n =
  Noise.Dh.key_exchange
    n.params.dh
    ~priv:(get_exn "e" n.e)
    ~pub:(get_exn "rs" n.rs)
  |> mix_key n

let encrypt_with_ad n0 plaintext =
  match n0.cipher_state with
  | Empty -> Ok (n0, plaintext)
  | Depleted -> Error "Nonce depleted"
  | Ready {key; nonce} ->
    let encrypt_result =
      Noise.Cipher.encrypt_with_ad
        n0.params.cipher
        ~key
        ~nonce
        ~ad:n0.h
        plaintext
    in
    encrypt_result >>= fun ciphertext_and_tag ->
    let n1 = incr_nonce n0 in
    Ok (n1, ciphertext_and_tag)

let encrypt_and_hash n0 payload =
  encrypt_with_ad n0 payload >>= fun (n1, ciphertext) ->
  let n2 = mix_hash n1 ciphertext in
  Ok (n2, ciphertext)

let init_handle_e_es n0 payload epub epriv =
  let (n1, msg0) = init_handle_e n0 epub epriv in
  let n2 = init_handle_es n1 in
  encrypt_and_hash n2 payload >>= fun (n3, msg1) ->
  Ok (n3, Cstruct.concat [msg0; msg1])

let build_test_case vector =
  let is_some = function
    | Some _ -> true
    | None -> false
  in
  vector.name >:: fun ctxt ->
    skip_if
      (is_some vector.init_psk)
      "PSK is not supported";
    match params vector with
    | Error e ->
      skip_if true e
    | Ok params ->
      begin
        match params.pattern with
        | N ->
          begin
            (* N:
               <- s
               ...
               -> e, es
            *)
            let resp_static = get_exn "resp_static" vector.resp_static in
            let static_pub = get_exn "init_remote_static" vector.init_remote_static in
            let h = prep_h vector.name params.hash in
            let responder =
              make_responder
                ~s:resp_static
                ~params
                ~h
                |> init_public_data
                  ~prologue:vector.resp_prologue
                ~s_pub:static_pub
            in
            assert (Noise.Dh_25519.corresponds ~priv:resp_static ~pub:static_pub);
            let first_msg = List.hd vector.messages in


            let initiator =
              let rs = get_exn "rs" vector.init_remote_static in
              make_init
                ~h
                ~rs
                ~params
              |> init_public_data
                ~prologue:vector.resp_prologue
                ~s_pub:rs
            in
            let (epub, _) = split_dh initiator.params first_msg.ciphertext in
            assert (Noise.Dh_25519.corresponds ~pub:epub
                      ~priv:vector.init_ephemeral);

            let initiator_result =
              init_handle_e_es
                initiator
                first_msg.payload
                epub
                vector.init_ephemeral
              >>= fun (n1, _) ->
              let final = {n1 with handshake_done = true} in
              Ok (final.cipher_state, get_handshake final)
            in

            let responder_result =
              responder_handle_e_es responder first_msg.ciphertext
              >>= fun (n1, (_:Cstruct.t)) ->
              let final_resp = {n1 with handshake_done = true} in
              Ok (final_resp.cipher_state, get_handshake final_resp)
            in

            assert_equal
              ~ctxt
              ~cmp:[%eq: Noise.Cipher_state.t * Test_helpers.Hex_string.t]
              ~printer:[%show: Noise.Cipher_state.t * Test_helpers.Hex_string.t]
              ~msg:"Final states should be equal"
              (get_result_exn "initiator" initiator_result)
              (get_result_exn "responder" responder_result)
          end
      end

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

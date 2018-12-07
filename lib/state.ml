open Util

type params =
  { dh : Dh.t
  ; cipher : Cipher.t
  ; hash : Hash.t }

type t =
  { re : Public_key.t option
  ; e : Private_key.t option
  ; rs : Public_key.t option
  ; s : Private_key.t option
  ; symmetric_state : Symmetric_state.t
  ; params : params
  ; cipher_state : Cipher_state.t
  ; transport_init_to_resp : Cipher_state.t option
  ; transport_resp_to_init : Cipher_state.t option
  ; is_initiator : bool
  ; pattern : Pattern.t
  ; remaining_handshake_steps : Pattern.step list list
  ; psk : Cstruct.t option }

let prep_h name hash =
  let buf_name = Cstruct.of_string name in
  let hashlen = Hash.len hash in
  let name_len = Cstruct.len buf_name in
  if name_len <= hashlen then (
    let buf = Cstruct.create hashlen in
    Cstruct.blit buf_name 0 buf 0 name_len;
    buf )
  else Hash.hash hash buf_name

let make ~name ~pattern ~is_initiator ~hash ~dh ~cipher ~s ~rs ~e ~psk =
  let h = prep_h name hash in
  let params = {hash; dh; cipher} in
  let symmetric_state = Symmetric_state.create hash dh h in
  { re = None
  ; e
  ; s
  ; rs
  ; params
  ; symmetric_state
  ; cipher_state = Cipher_state.empty
  ; transport_init_to_resp = None
  ; transport_resp_to_init = None
  ; is_initiator
  ; pattern
  ; remaining_handshake_steps = Pattern.all_steps pattern
  ; psk }

let public_key_opt dh = function
  | Some priv ->
      Some (Dh.public_key dh priv)
  | None ->
      None

let e_pub state = public_key_opt state.params.dh state.e

let s_pub state = public_key_opt state.params.dh state.s

let is_initiator state = state.is_initiator

let pattern state = state.pattern

let split_dh ?(clear = false) s msg =
  let dh_len = Dh.len s.params.dh in
  let len =
    if clear then dh_len
    else if Cipher_state.has_key s.cipher_state then dh_len + 16
    else dh_len
  in
  let a, b = Cstruct.split msg len in
  (Public_key.of_bytes a, b)

let mix_hash s data =
  {s with symmetric_state = Symmetric_state.mix_hash s.symmetric_state data}

let set_symmetric_state_and_key s (symmetric_state, key) =
  {s with cipher_state = Cipher_state.create key; symmetric_state}

let mix_key s input =
  Symmetric_state.mix_key s.symmetric_state input
  |> set_symmetric_state_and_key s

let mix_hash_and_psk s0 key =
  let input = Public_key.bytes key in
  let s1 = mix_hash s0 input in
  match s1.psk with
  | Some _ ->
      mix_key s1 input
  | None ->
      s1

let get_psk s =
  match s.psk with
  | Some psk ->
      Ok psk
  | None ->
      Error "no psk"

let mix_key_and_hash_psk s =
  let%map psk = get_psk s in
  Symmetric_state.mix_key_and_hash s.symmetric_state psk
  |> set_symmetric_state_and_key s

type key_type =
  | Static
  | Ephemeral

let key_or_error key_opt name =
  match key_opt with
  | None ->
      Error (Printf.sprintf "%s is not set" name)
  | Some k ->
      Ok k

let local_key s = function
  | Static ->
      key_or_error s.s "s"
  | Ephemeral ->
      key_or_error s.e "e"

let remote_key s = function
  | Static ->
      key_or_error s.rs "rs"
  | Ephemeral ->
      key_or_error s.re "re"

let mix_dh_key s ~local ~remote =
  let%bind priv = local_key s local in
  let%bind pub = remote_key s remote in
  Dh.key_exchange s.params.dh ~priv ~pub |> mix_key s |> fun x -> Ok x

let has_dh_size s k = Cstruct.len (Public_key.bytes k) = Dh.len s.params.dh

let set_re s k =
  assert (has_dh_size s k);
  match s.re with
  | None ->
      Ok {s with re = Some k}
  | Some _ ->
      Error "re is already set"

let set_rs s k =
  assert (has_dh_size s k);
  match s.rs with
  | None ->
      Ok {s with rs = Some k}
  | Some _ ->
      Error "rs is already set"

let decrypt_with_ad_cs cipher_state ~ad cipher =
  Cipher_state.with_ cipher_state (Cipher.decrypt_with_ad cipher ~ad)

let decrypt_with_ad s ciphertext_and_tag =
  let%map new_cs, plaintext =
    decrypt_with_ad_cs s.cipher_state
      ~ad:(Symmetric_state.h s.symmetric_state)
      s.params.cipher ciphertext_and_tag
  in
  ({s with cipher_state = new_cs}, plaintext)

let handshake_hash s =
  match s.transport_init_to_resp with
  | None ->
      None
  | Some _ ->
      Some (Symmetric_state.h s.symmetric_state)

type state =
  | Handshake_step of Pattern.step list * bool
  | Transport

let next s =
  match s.remaining_handshake_steps with
  | h :: t ->
      let is_last = t = [] in
      ({s with remaining_handshake_steps = t}, Handshake_step (h, is_last))
  | [] ->
      (s, Transport)

let decrypt_and_hash s0 ciphertext =
  let%map s1, plaintext = decrypt_with_ad s0 ciphertext in
  (mix_hash s1 ciphertext, plaintext)

let encrypt_with_ad_cs cipher_state ~ad cipher =
  Cipher_state.with_ cipher_state (Cipher.encrypt_with_ad cipher ~ad)

let encrypt_with_ad s plaintext =
  let%map new_cs, ciphertext =
    encrypt_with_ad_cs s.cipher_state
      ~ad:(Symmetric_state.h s.symmetric_state)
      s.params.cipher plaintext
  in
  ({s with cipher_state = new_cs}, ciphertext)

let encrypt_and_hash s payload =
  let%map n1, ciphertext = encrypt_with_ad s payload in
  (mix_hash n1 ciphertext, ciphertext)

let transport_encrypt s plaintext cipher_state =
  encrypt_with_ad_cs cipher_state ~ad:Cstruct.empty s.params.cipher plaintext

let transport_decrypt s ciphertext cipher_state =
  decrypt_with_ad_cs cipher_state ~ad:Cstruct.empty s.params.cipher ciphertext

let get_transport_init_to_resp s = s.transport_init_to_resp

let set_transport_init_to_resp s v = {s with transport_init_to_resp = v}

let get_transport_resp_to_init s = s.transport_resp_to_init

let set_transport_resp_to_init s v = {s with transport_resp_to_init = v}

let with_ s ~send =
  let get, set =
    if s.is_initiator = send then
      (get_transport_init_to_resp, set_transport_init_to_resp)
    else (get_transport_resp_to_init, set_transport_resp_to_init)
  in
  fun k ->
    match get s with
    | Some cipher_state ->
        let%map new_cs, result = k cipher_state in
        (set s (Some new_cs), result)
    | None ->
        Error "Transport is not setup"

let setup_transport s =
  let init_to_resp, resp_to_init = Symmetric_state.split s.symmetric_state in
  match Pattern.transport s.pattern with
  | One_way ->
      {s with transport_init_to_resp = Some init_to_resp}
  | Two_way ->
      { s with
        transport_init_to_resp = Some init_to_resp
      ; transport_resp_to_init = Some resp_to_init }

let send_transport s plaintext =
  with_ s ~send:true @@ transport_encrypt s plaintext

let receive_transport s ciphertext =
  with_ s ~send:false @@ transport_decrypt s ciphertext

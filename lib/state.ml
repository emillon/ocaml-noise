open Util

type params =
  { dh : Dh.t
  ; cipher : Cipher.t
  ; hash : Hash.t
  }

type t =
  { re : Public_key.t option
  ; e : Private_key.t option
  ; rs : Public_key.t option
  ; s : Private_key.t option
  ; symmetric_state : Symmetric_state.t
  ; params : params
  ; cipher_state : Cipher_state.t
  ; transport_init_to_resp : Cipher_state.t option
  ; is_initiator : bool
  ; pattern : Pattern.t
  ; remaining_handshake_steps : Pattern.step list list
  }

let prep_h name hash =
  let buf_name = Cstruct.of_string name in
  let hashlen = Hash.len hash in
  let name_len = Cstruct.len buf_name in
  if name_len <= hashlen then
    let buf = Cstruct.create hashlen in
    Cstruct.blit buf_name 0 buf 0 name_len;
    buf
  else
    Hash.hash hash buf_name

let make ~name ~pattern ~is_initiator ~hash ~dh ~cipher ~s ~rs ~e =
  let h = prep_h name hash in
  let params =
    { hash
    ; dh
    ; cipher
    }
  in
  let symmetric_state =
    Symmetric_state.create
      hash
      dh
      h
  in
  { re = None
  ; e
  ; s
  ; rs
  ; params
  ; symmetric_state
  ; cipher_state = Cipher_state.empty
  ; transport_init_to_resp = None
  ; is_initiator
  ; pattern
  ; remaining_handshake_steps = Pattern.all_steps pattern
  }

let public_key_opt = function
  | Some priv -> Some (Dh_25519.public_key priv)
  | None -> None

let e_pub state =
  public_key_opt state.e

let s_pub state =
  public_key_opt state.s

let is_initiator state =
  state.is_initiator

let pattern state =
  state.pattern

let split_dh s msg =
  let dh_len = Dh.len s.params.dh in
  let len =
    if Cipher_state.has_key s.cipher_state then
      dh_len + 16
    else
      dh_len
  in
  let (a, b) = Cstruct.split msg len in
  (Public_key.of_bytes a, b)

let mix_hash s data =
  { s with
    symmetric_state =
      Symmetric_state.mix_hash
        s.symmetric_state
        data
  }

let mix_key s input =
  let (new_symmetric_state, new_key) =
    Symmetric_state.mix_key
      s.symmetric_state
      input
  in
  { s with
      cipher_state = Cipher_state.create new_key
    ; symmetric_state = new_symmetric_state
  }

type key_type = Static | Ephemeral

let key_or_error key_opt name =
  match key_opt with
  | None -> Error (Printf.sprintf "%s is not set" name)
  | Some k -> Ok k

let local_key s = function
  | Static -> key_or_error s.s "s"
  | Ephemeral -> key_or_error s.e "e"

let remote_key s = function
  | Static -> key_or_error s.rs "rs"
  | Ephemeral -> key_or_error s.re "re"

let mix_dh_key s ~local ~remote =
  local_key s local >>= fun priv ->
  remote_key s remote >>= fun pub ->
  Dh.key_exchange
    s.params.dh
    ~priv
    ~pub
  |> mix_key s
  |> fun x -> Ok x

let set_re s k =
  match s.re with
  | None -> Ok { s with re = Some k }
  | Some _ -> Error "re is already set"

let set_rs s k =
  match s.rs with
  | None -> Ok { s with rs = Some k }
  | Some _ -> Error "rs is already set"

let decrypt_with_ad_cs cipher_state ~ad cipher =
  Cipher_state.with_ cipher_state
    (Cipher.decrypt_with_ad cipher ~ad)

let decrypt_with_ad s ciphertext_and_tag =
  decrypt_with_ad_cs
    s.cipher_state
    ~ad:(Symmetric_state.h s.symmetric_state)
    s.params.cipher
    ciphertext_and_tag
  >>| fun (new_cs, plaintext) ->
  ({s with cipher_state = new_cs}, plaintext)

type state =
  | Handshake_not_done
  | One_way_transport

let state s =
  match s.transport_init_to_resp with
  | None -> Handshake_not_done
  | Some _ -> One_way_transport

let handshake_hash s =
  match state s with
  | Handshake_not_done -> None
  | One_way_transport -> Some (Symmetric_state.h s.symmetric_state)

let pop_handshake_step s =
  match s.remaining_handshake_steps with
  | [] -> Error "Handshake complete"
  | h::t -> Ok ({s with remaining_handshake_steps = t}, h)

let decrypt_and_hash s0 ciphertext =
  decrypt_with_ad s0 ciphertext >>| fun (s1, plaintext) ->
  (mix_hash s1 ciphertext, plaintext)

let encrypt_with_ad_cs cipher_state ~ad cipher =
  Cipher_state.with_ cipher_state
    (Cipher.encrypt_with_ad cipher ~ad)

let encrypt_with_ad s plaintext =
  encrypt_with_ad_cs
    s.cipher_state
    ~ad:(Symmetric_state.h s.symmetric_state)
    s.params.cipher
    plaintext
  >>| fun (new_cs, ciphertext) ->
  ({s with cipher_state = new_cs }, ciphertext)

let encrypt_and_hash s payload =
  encrypt_with_ad s payload >>| fun (n1, ciphertext) ->
  (mix_hash n1 ciphertext, ciphertext)

module One_way_transport = struct
  let with_init_to_resp s k =
    match s.transport_init_to_resp with
    | Some cipher_state ->
      k cipher_state >>| fun (new_cs, result) ->
      ( { s with
          transport_init_to_resp = Some new_cs
        }
      , result
      )
    | None ->
      Error "Handshake not finished"

  let setup s =
    let (init_to_resp, _) =
      Symmetric_state.split s.symmetric_state
    in
    { s with
      transport_init_to_resp = Some init_to_resp
    }

  let send s plaintext =
    if s.is_initiator then
      with_init_to_resp s @@ fun cipher_state ->
      encrypt_with_ad_cs
        cipher_state
        ~ad:Cstruct.empty
        s.params.cipher
        plaintext
    else
      Error "one way transport: cannot send"

  let receive s ciphertext =
    if s.is_initiator then
      Error "one way transport: cannot receive"
    else
      with_init_to_resp s @@ fun cipher_state ->
      decrypt_with_ad_cs
        cipher_state
        ~ad:Cstruct.empty
        s.params.cipher
        ciphertext
end

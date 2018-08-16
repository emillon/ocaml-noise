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
  ; transport : Cipher_state.t option
  }

let e s = s.e
let s s = s.s
let re s = s.re
let rs s = s.rs

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

let make ~name ~hash ~dh ~cipher ~s ~rs ~e =
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
  ; transport = None
  }

let public_key_opt = function
  | Some priv -> Some (Dh_25519.public_key priv)
  | None -> None

let e_pub state =
  public_key_opt state.e

let s_pub state =
  public_key_opt state.s

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

let mix_dh_key s ~priv ~pub =
  Dh.key_exchange
    s.params.dh
    ~priv
    ~pub
  |> mix_key s

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

let handshake_hash s =
  match s.transport with
  | Some _ -> Some (Symmetric_state.h s.symmetric_state)
  | None -> None

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
  let with_ s k =
    match s.transport with
    | Some cipher_state ->
      k cipher_state >>| fun (new_cs, result) ->
      ( { s with
          transport = Some new_cs
        }
      , result
      )
    | None ->
      Error "Handshake not finished"

  let setup s =
    { s with
      transport =
        Some
          (Symmetric_state.split_one_way s.symmetric_state)
    }

  let send s plaintext =
    with_ s @@ fun cipher_state ->
    encrypt_with_ad_cs
      cipher_state
      ~ad:Cstruct.empty
      s.params.cipher
      plaintext

  let receive s ciphertext =
    with_ s @@ fun cipher_state ->
    decrypt_with_ad_cs
      cipher_state
      ~ad:Cstruct.empty
      s.params.cipher
      ciphertext
end

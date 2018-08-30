type t =
  { ck : Cstruct.t
  ; h : Cstruct.t
  ; hash : Hash.t
  ; dh : Dh.t }

let h t = t.h

let create hash dh h = {ck = h; h; hash; dh}

let mix_hash s data =
  let new_h = Hash.hash s.hash (Cstruct.concat [s.h; data]) in
  {s with h = new_h}


let truncate_if_hash_64 s input =
  if Hash.len s.hash = 64 then Cstruct.sub input 0 32 else input


let hkdf_gen hkdf s input =
  let {ck; hash; dh; _} = s in
  let hashlen = Hash.len hash in
  let ikm_length = Cstruct.len input in
  let dh_len = Dh.len dh in
  assert (Cstruct.len ck = hashlen);
  assert (List.mem ikm_length [0; 32; dh_len]);
  hkdf ~hmac:(Hash.hmac hash) ~salt:ck ~ikm:input


let hkdf2 = hkdf_gen Hkdf.hkdf2

let hkdf3 = hkdf_gen Hkdf.hkdf3

let mix_key s input =
  let new_ck, temp_k = hkdf2 s input in
  let new_s = {s with ck = new_ck} in
  let truncated_temp_k = truncate_if_hash_64 new_s temp_k in
  (new_s, Private_key.of_bytes truncated_temp_k)


let split s =
  let make_cipher_state temp_k =
    temp_k
    |> truncate_if_hash_64 s
    |> Private_key.of_bytes
    |> Cipher_state.create
  in
  let temp_k1, temp_k2 = hkdf2 s Cstruct.empty in
  (make_cipher_state temp_k1, make_cipher_state temp_k2)


let mix_key_and_hash s0 input =
  let new_ck, temp_h, temp_k = hkdf3 s0 input in
  let s1 = {s0 with ck = new_ck} in
  let s2 = mix_hash s1 temp_h in
  let truncated_temp_k = truncate_if_hash_64 s2 temp_k in
  (s2, Private_key.of_bytes truncated_temp_k)

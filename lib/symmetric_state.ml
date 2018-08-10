type t =
  { ck : Cstruct.t
  ; h : Cstruct.t
  ; hash : Hash.t
  ; dh : Dh.t
  }

let h t = t.h

let create hash dh h =
  { ck = h
  ; h
  ; hash
  ; dh
  }

let mix_hash s data =
  let new_h =
    Hash.hash s.hash (Cstruct.concat [s.h; data])
  in
  {s with h = new_h}

let truncate_if_hash_64 s input =
  if Hash.len s.hash = 64 then
    Cstruct.sub input 0 32
  else
    input

let hkdf2 {ck; hash; dh; _} input =
  let hashlen = Hash.len hash in
  let ikm_length = Cstruct.len input in
  let dh_len = Dh.len dh in
  assert (Cstruct.len ck = hashlen);
  assert (List.mem ikm_length [0; 32; dh_len]);
  Hkdf.hkdf2
    ~hmac:(Hash.hmac hash)
    ~salt:ck
    ~ikm:input

let mix_key s input =
  let (new_ck, temp_k) = hkdf2 s input in
  let new_s = {s with ck = new_ck} in
  let truncated_temp_k = truncate_if_hash_64 new_s temp_k in
  (new_s, Private_key.of_bytes truncated_temp_k)

let split_one_way s =
  let (temp_k1, _) = hkdf2 s Cstruct.empty in
  let temp_k1 = truncate_if_hash_64 s temp_k1 in
  let transport_key1 = Private_key.of_bytes temp_k1 in
  Cipher_state.create transport_key1

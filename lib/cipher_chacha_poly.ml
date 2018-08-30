open Util

let pad16 x =
  let len = Cstruct.len x in
  let lenmod16 = len mod 16 in
  if lenmod16 = 0 then Cstruct.empty else Cstruct.create (16 - lenmod16)


let num_to_8_le_bytes n =
  let cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 cs 0 (Int64.of_int n);
  cs


let key_gen ~key ~nonce =
  let%map s0 = Chacha20.make_state_for_encryption ~key ~nonce ~count:0l in
  let s1 = Chacha20.process s0 in
  Cstruct.sub (Chacha20.serialize s1) 0 32


let compute_tag ~otk ~ad ~ciphertext =
  let mac_data =
    Cstruct.concat
      [ ad
      ; pad16 ad
      ; ciphertext
      ; pad16 ciphertext
      ; num_to_8_le_bytes (Cstruct.len ad)
      ; num_to_8_le_bytes (Cstruct.len ciphertext) ]
  in
  Tweetnacl.poly1305 ~key:otk mac_data


let encrypt_with_ad_low ~key ~fixed ~iv ~ad plaintext =
  let key = Private_key.bytes key in
  let nonce = Cstruct.concat [fixed; iv] in
  let%bind otk = key_gen ~key ~nonce in
  let%map ciphertext = Chacha20.encrypt ~key ~counter:1l ~nonce plaintext in
  let tag = compute_tag ~otk ~ad ~ciphertext in
  (ciphertext, tag)


let encode_iv nonce =
  let iv = Cstruct.create 8 in
  Cstruct.LE.set_uint64 iv 0 nonce;
  iv


let encrypt_with_ad ~key ~nonce ~ad plaintext =
  let%map ciphertext, tag =
    encrypt_with_ad_low ~key ~ad ~fixed:(Cstruct.create 4)
      ~iv:(encode_iv nonce) plaintext
  in
  Cstruct.concat [ciphertext; tag]


let split ciphertext_and_tag =
  let tag_len = 128 / 8 in
  let ciphertext_len = Cstruct.len ciphertext_and_tag - tag_len in
  if ciphertext_len < 0 then Error "Ciphertext is too short"
  else Ok (Cstruct.split ciphertext_and_tag ciphertext_len)


let encode_nonce n =
  let nonce = Cstruct.create 12 in
  Cstruct.LE.set_uint64 nonce 4 n;
  nonce


let decrypt_with_ad ~key ~nonce ~ad ciphertext_and_tag =
  let key = Private_key.bytes key in
  let nonce = encode_nonce nonce in
  let%bind ciphertext, received_tag = split ciphertext_and_tag in
  let%bind otk = key_gen ~key ~nonce in
  let expected_tag = compute_tag ~otk ~ad ~ciphertext in
  if equal_constant_time expected_tag received_tag then
    Chacha20.encrypt ~key ~counter:1l ~nonce ciphertext
  else Error "Wrong tag"

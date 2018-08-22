open Util

let pad16 x =
  let len = Cstruct.len x in
  let lenmod16 = len mod 16 in
  if lenmod16 = 0 then
    Cstruct.empty
  else
    Cstruct.create (16 - lenmod16)

let num_to_8_le_bytes n =
  let cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 cs 0 (Int64.of_int n);
  cs

let key_gen ~key ~nonce =
  Chacha20.make_state_for_encryption ~key ~nonce ~count:0l >>| fun s0 ->
  let s1 = Chacha20.process s0 in
  Cstruct.sub (Chacha20.serialize s1) 0 32

let encrypt_with_ad_low ~key ~fixed ~iv ~ad plaintext =
  let key = Private_key.bytes key in
  let nonce = Cstruct.concat [fixed; iv] in
  key_gen ~key ~nonce >>= fun otk ->
  Chacha20.encrypt
    ~key
    ~counter:1l
    ~nonce
    plaintext
  >>| fun ciphertext ->
  let mac_data =
    Cstruct.concat
      [ ad
      ; pad16 ad
      ; ciphertext
      ; pad16 ciphertext
      ; num_to_8_le_bytes (Cstruct.len ad)
      ; num_to_8_le_bytes (Cstruct.len ciphertext)
      ]
  in
  let tag = Tweetnacl.poly1305 ~key:otk mac_data in
  (ciphertext, tag)

let encode_iv nonce =
  let iv = Cstruct.create 8 in
  Cstruct.LE.set_uint64 iv 0 nonce;
  iv

let encrypt_with_ad ~key ~nonce ~ad plaintext =
  encrypt_with_ad_low
    ~key
    ~ad
    ~fixed:(Cstruct.create 4)
    ~iv:(encode_iv nonce)
    plaintext
  >>| fun (ciphertext, tag) ->
  (Cstruct.concat [ciphertext; tag])

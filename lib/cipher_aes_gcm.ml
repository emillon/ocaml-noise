let iv ~nonce =
  let buf = Cstruct.create 12 in
  Cstruct.BE.set_uint64 buf 4 nonce;
  buf

let make_key key =
  let open Nocrypto.Cipher_block.AES.GCM in
  let private_bytes = Private_key.bytes key in
  match of_secret private_bytes with
  | key -> Ok key
  | exception Invalid_argument _ -> Error "Wrong key size"

let encrypt_with_ad ~key ~nonce ~ad plaintext =
  let open Nocrypto.Cipher_block.AES.GCM in
  match make_key key with
  | Error _ as e -> e
  | Ok key ->
    let iv = iv ~nonce in
    let result = encrypt ~key ~adata:ad ~iv plaintext in
    Ok (Cstruct.concat [result.message; result.tag])

let decrypt_with_ad ~key ~nonce ~ad ciphertext_and_tag =
  let open Nocrypto.Cipher_block.AES.GCM in
  match make_key key with
  | Error _ as e -> e
  | Ok key ->
    let iv = iv ~nonce in
    let tag_len = 128 / 8 in
    let ciphertext_len = Cstruct.len ciphertext_and_tag - tag_len in
    if ciphertext_len < 0 then
      Error "Ciphertext is too short"
    else
      let (ciphertext, tag) = Cstruct.split ciphertext_and_tag ciphertext_len in
      let result = decrypt ~key ~adata:ad ~iv ciphertext in
      if Cstruct.equal result.tag tag then
        Ok result.message
      else
        Error "Wrong tag"

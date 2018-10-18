let to_cstruct d = Cstruct.of_string @@ Digestif.BLAKE2B.to_raw_string d

let hash data =
  Cstruct.to_string data |> Digestif.BLAKE2B.digest_string |> to_cstruct


let block_len = 128

let hmac = Hash_hmac.hmac ~block_len hash

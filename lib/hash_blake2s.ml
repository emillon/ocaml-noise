let to_cstruct (d : Digestif.BLAKE2S.t) = Cstruct.of_string (d :> string)

let hash data =
  Cstruct.to_string data |> Digestif.BLAKE2S.digest_string |> to_cstruct


let block_len = 64

let hmac = Hash_hmac.hmac ~block_len hash

let to_cstruct d = Cstruct.of_string @@ Digestif.BLAKE2B.to_raw_string d

let hash data =
  Cstruct.to_string data |> Digestif.BLAKE2B.digest_string |> to_cstruct


let hmac ~key data =
  let string_key = Cstruct.to_string key in
  Cstruct.to_string data
  |> Digestif.BLAKE2B.hmac_string ~key:string_key
  |> to_cstruct

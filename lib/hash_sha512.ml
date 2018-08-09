let digest_to_string d =
  let from_hex_string s =
    Hex.to_cstruct (`Hex s)
  in
  Digestif.SHA512.to_hex d
  |> from_hex_string

let hash data =
  Cstruct.to_string data
  |> Digestif.SHA512.digest_string
  |> digest_to_string

let hmac ~key data =
  let string_key = Cstruct.to_string key in
  Cstruct.to_string data
  |> Digestif.SHA512.hmac_string ~key:string_key
  |> digest_to_string

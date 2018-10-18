let to_cstruct d = Cstruct.of_string @@ Digestif.SHA256.to_raw_string d

let hash data =
  Cstruct.to_string data |> Digestif.SHA256.digest_string |> to_cstruct


let hmac ~key data =
  let string_key = Cstruct.to_string key in
  Cstruct.to_string data
  |> Digestif.SHA256.hmac_string ~key:string_key
  |> to_cstruct
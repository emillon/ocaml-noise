let to_cstruct (d : Digestif.SHA512.t) = Cstruct.of_string (d :> string)

let hash data =
  Cstruct.to_string data |> Digestif.SHA512.digest_string |> to_cstruct


let hmac ~key data =
  let string_key = Cstruct.to_string key in
  Cstruct.to_string data
  |> Digestif.SHA512.hmac_string ~key:string_key
  |> to_cstruct

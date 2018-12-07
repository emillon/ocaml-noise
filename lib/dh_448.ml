let hex_encode cs =
  let (`Hex h) = Hex.of_cstruct cs in
  h

let private_key_noise_to_lib key =
  key |> Private_key.bytes |> hex_encode |> Rfc7748.X448.private_key_of_string

let public_key_lib_to_cstruct key =
  key |> Rfc7748.X448.string_of_public_key |> Cstruct.of_hex

let public_key_lib_to_noise key =
  key |> public_key_lib_to_cstruct |> Public_key.of_bytes

let public_key_noise_to_lib key =
  key |> Public_key.bytes |> hex_encode |> Rfc7748.X448.public_key_of_string

let public_key priv =
  priv
  |> private_key_noise_to_lib
  |> Rfc7748.X448.public_key_of_private_key
  |> public_key_lib_to_noise

let corresponds ~priv ~pub =
  let computed_key = public_key priv in
  Public_key.equal computed_key pub

let key_exchange ~priv ~pub =
  Rfc7748.X448.scale
    (private_key_noise_to_lib priv)
    (public_key_noise_to_lib pub)
  |> public_key_lib_to_cstruct

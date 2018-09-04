let key_size = 32

let with_temp_array k =
  let a = Array.make key_size 0 in
  k a;
  let cs = Cstruct.create key_size in
  Array.iteri (Cstruct.set_uint8 cs) a;
  cs


let convert_public pub =
  Callipyge.public_key_of_string @@ Cstruct.to_string @@ Public_key.bytes pub


let convert_secret priv =
  Callipyge.secret_key_of_string
  @@ Cstruct.to_string
  @@ Private_key.bytes priv


let key_exchange ~priv ~pub =
  let public = convert_public pub in
  let secret = convert_secret priv in
  with_temp_array @@ fun out -> Callipyge.ecdh_inplace ~out ~secret ~public


let public_key_cs priv =
  let secret = convert_secret priv in
  with_temp_array @@ fun out -> Callipyge.ecdh_base_inplace ~out ~secret


let public_key priv = Public_key.of_bytes (public_key_cs priv)

let corresponds ~priv ~pub =
  let computed_pub = public_key_cs priv in
  Cstruct.equal (Public_key.bytes pub) computed_pub

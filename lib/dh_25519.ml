let key_exchange ~priv ~pub =
  Tweetnacl.scalar_mult
    ~priv:(Private_key.bytes priv)
    ~pub:(Public_key.bytes pub)

let public_key_cs priv =
  let base = Cstruct.create 32 in
  Cstruct.set_uint8 base 0 9;
  let pub_base = Public_key.of_bytes base in
  key_exchange ~priv ~pub:pub_base

let public_key priv =
  Public_key.of_bytes (public_key_cs priv)

let corresponds ~priv ~pub =
  let computed_pub = public_key_cs priv in
  Cstruct.equal (Public_key.bytes pub) computed_pub

let key_exchange ~priv ~pub =
  Tweetnacl.scalar_mult
    ~priv:(Private_key.bytes priv)
    ~pub:(Public_key.bytes pub)

let corresponds ~priv ~pub =
  let base = Cstruct.create 32 in
  Cstruct.set_uint8 base 0 9;
  let pub_base = Public_key.of_bytes base in
  let computed_pub = key_exchange ~priv ~pub:pub_base in
  Cstruct.equal (Public_key.bytes pub) computed_pub

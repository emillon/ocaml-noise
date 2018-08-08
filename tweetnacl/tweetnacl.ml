external caml_tweetnacl_scalar_mult :
  Cstruct.buffer ->
  Cstruct.buffer ->
  Cstruct.buffer ->
  unit
  = "caml_tweetnacl_scalar_mult"

exception Wrong_key_size

let scalar_mult ~pub ~priv =
  let key_size = 32 in
  let ok cs = Cstruct.len cs = key_size in
  let sizes_ok = ok priv && ok pub in
  if not sizes_ok then
    raise Wrong_key_size;
  let pub_buffer = Cstruct.to_bigarray pub in
  let priv_buffer = Cstruct.to_bigarray priv in
  let into = Cstruct.create key_size in
  let into_buffer = Cstruct.to_bigarray into in
  caml_tweetnacl_scalar_mult into_buffer priv_buffer pub_buffer;
  into

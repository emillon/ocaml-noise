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

external caml_tweetnacl_poly1305:
  Cstruct.buffer ->
  Cstruct.buffer ->
  int64 ->
  Cstruct.buffer ->
  unit
  = "caml_tweetnacl_poly1305"

let poly1305 ~key msg =
  let poly1305_key_length = 32 in
  let poly1305_output_length = 16 in
  if Cstruct.len key <> poly1305_key_length then
    raise Wrong_key_size;
  let key_buffer = Cstruct.to_bigarray key in
  let result = Cstruct.create poly1305_output_length in
  let result_buffer = Cstruct.to_bigarray result in
  let msg_len = Int64.of_int @@ Cstruct.len msg in
  let msg_buffer = Cstruct.to_bigarray msg in
  caml_tweetnacl_poly1305 result_buffer msg_buffer msg_len key_buffer;
  result

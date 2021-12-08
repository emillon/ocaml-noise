exception Wrong_key_size

external caml_tweetnacl_poly1305 :
  Cstruct.buffer -> Cstruct.buffer -> int64 -> Cstruct.buffer -> unit
  = "caml_tweetnacl_poly1305"

let poly1305 ~key msg =
  let poly1305_key_length = 32 in
  let poly1305_output_length = 16 in
  if Cstruct.length key <> poly1305_key_length then raise Wrong_key_size;
  let key_buffer = Cstruct.to_bigarray key in
  let result = Cstruct.create poly1305_output_length in
  let result_buffer = Cstruct.to_bigarray result in
  let msg_len = Int64.of_int @@ Cstruct.length msg in
  let msg_buffer = Cstruct.to_bigarray msg in
  caml_tweetnacl_poly1305 result_buffer msg_buffer msg_len key_buffer;
  result

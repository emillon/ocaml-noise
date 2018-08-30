let right_pad ~block_len key =
  let n = Cstruct.len key in
  let cs = Cstruct.create block_len in
  Cstruct.blit key 0 cs 0 n; cs


let prepare_key ~block_len hash key =
  let n = Cstruct.len key in
  if n = block_len then key
  else if n > block_len then hash key
  else right_pad ~block_len key


let cstruct_xor cs byte =
  let n = Cstruct.len cs in
  let out = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 out i (byte lxor Cstruct.get_uint8 cs i)
  done;
  out


let hmac ~block_len hash ~key data =
  let ( || ) x y = Cstruct.concat [x; y] in
  let ( <+> ) = cstruct_xor in
  let k = prepare_key ~block_len hash key in
  hash (k <+> 0x5c || hash (k <+> 0x36 || data))

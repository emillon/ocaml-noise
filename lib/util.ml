let (>>=) x f =
  match x with
  | Ok x -> f x
  | Error _ as e -> e

let (>>|) x f =
  x >>= fun y -> Ok (f y)

let equal_constant_time a b =
  let len_a = Cstruct.len a in
  let len_b = Cstruct.len b in
  if len_a <> len_b then
    false
  else
    let r = ref 0 in
    for i = 0 to len_a - 1 do
      let byte_a = Cstruct.get_uint8 a i in
      let byte_b = Cstruct.get_uint8 b i in
      let byte_diff = byte_a lxor byte_b in
      r := !r lor byte_diff
    done;
    !r = 0

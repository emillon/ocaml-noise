let rotate_left n b =
  let open Int32 in
  let hi = shift_left n b in
  let lo = shift_right_logical n (32 - b) in
  logor hi lo

let quarter_round (a, b, c, d) =
  let open Int32 in
  (*1. a += b; d ^= a; d <<<= 16;*)
  let a = add a b in
  let d = logxor d a in
  let d = rotate_left d 16 in

  (*2.  c += d; b ^= c; b <<<= 12;*)
  let c = add c d in
  let b = logxor b c in
  let b = rotate_left b 12 in

  (*3.  a += b; d ^= a; d <<<= 8;*)
  let a = add a b in
  let d = logxor d a in
  let d = rotate_left d 8 in

  (*4.  c += d; b ^= c; b <<<= 7;*)
  let c = add c d in
  let b = logxor b c in
  let b = rotate_left b 7 in

  (a, b, c, d)

type state = int32 array
[@@deriving eq,show]

let make_state l =
  if List.length l = 16 then
    Array.of_list l
  else
    invalid_arg "make_state"

let get s i =
  Array.get s i

let set i v s =
  let f j =
    if i = j then
      v
    else
      get s j
  in
  Array.init 16 f

let quarter_round_state s (ia, ib, ic, id) =
  let a = get s ia in
  let b = get s ib in
  let c = get s ic in
  let d = get s id in
  let (na, nb, nc, nd) = quarter_round (a, b, c, d) in
  s
  |> set ia na
  |> set ib nb
  |> set ic nc
  |> set id nd

let make_state_for_encryption ~key ~nonce ~count =
  if Cstruct.len key <> 32 then
    Error "wrong key length"
  else if Cstruct.len nonce <> 12 then
    Error "wrong nonce length"
  else
    let constant_words =
      [ 0x61707865l
      ; 0x3320646el
      ; 0x79622d32l
      ; 0x6b206574l
      ]
    in
    let key_words =
      [ Cstruct.LE.get_uint32 key 0
      ; Cstruct.LE.get_uint32 key 4
      ; Cstruct.LE.get_uint32 key 8
      ; Cstruct.LE.get_uint32 key 12
      ; Cstruct.LE.get_uint32 key 16
      ; Cstruct.LE.get_uint32 key 20
      ; Cstruct.LE.get_uint32 key 24
      ; Cstruct.LE.get_uint32 key 28
      ]
    in
    let count_words =
      [ count
      ]
    in
    let nonce_words =
      [ Cstruct.LE.get_uint32 nonce 0
      ; Cstruct.LE.get_uint32 nonce 4
      ; Cstruct.LE.get_uint32 nonce 8
      ]
    in
    Ok (
      make_state @@
      List.concat
        [ constant_words
        ; key_words
        ; count_words
        ; nonce_words
        ]
    )

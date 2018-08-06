type t = 
  | N
  | X
  | K
  | NN
  | NK
  | NX
  | XN
  | XK
  | XX
  | KN
  | KK
  | KX
  | IN
  | IK
  | IX
[@@deriving eq,show]

val of_string : string -> (t, string) result

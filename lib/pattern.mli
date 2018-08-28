type t =
  | N
  | K
  | X
  | NN
  | NX
  | IN
  | XN
  | XX
  | IX
  | NK
  | IK
  | KN
  | KK
  | KX
  | XK
  | IKpsk1
  | IKpsk2
  | INpsk1
  | INpsk2
  | IXpsk2
  | KKpsk0
  | KKpsk2
  | KNpsk0
  | KNpsk2
  | KXpsk2
  | NKpsk0
  | NKpsk2
  | NNpsk0
  | NNpsk2
  | NXpsk2
  | XKpsk3
  | XNpsk3
  | XXpsk3
  | Npsk0
  | Xpsk1
  | Kpsk0
[@@deriving eq,show]

val of_string : string -> (t, string) result

type step =
  | E
  | ES
  | S
  | SS
  | EE
  | SE
  | PSK

val all_steps : t -> step list list

type transport =
  | One_way
  | Two_way

val transport : t -> transport

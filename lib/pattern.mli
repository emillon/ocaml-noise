type t =
  | N
  | K
  | X
  | NN
  | NX
[@@deriving eq,show]

val of_string : string -> (t, string) result

type step =
  | E
  | ES
  | S
  | SS
  | EE

val all_steps : t -> step list list

type transport =
  | One_way
  | Two_way

val transport : t -> transport

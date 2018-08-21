type t =
  | N
  | K
  | X
[@@deriving eq,show]

val of_string : string -> (t, string) result

type step =
  | E
  | ES
  | S
  | SS

val all_steps : t -> step list list

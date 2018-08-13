type t =
  | N
  | K
  | X
[@@deriving eq,show]

val of_string : string -> (t, string) result

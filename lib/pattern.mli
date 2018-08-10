type t =
  | N
  | K
[@@deriving eq,show]

val of_string : string -> (t, string) result

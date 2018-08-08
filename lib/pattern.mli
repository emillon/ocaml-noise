type t =
  | N
[@@deriving eq,show]

val of_string : string -> (t, string) result

type t =
  | Curve_25519
  | Curve_448
[@@deriving eq,show]

val of_string : string -> (t, string) result

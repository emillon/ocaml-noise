type t =
  | BLAKE2s
  | BLAKE2b
  | SHA256
  | SHA512
[@@deriving eq,show]

val of_string : string -> (t, string) result

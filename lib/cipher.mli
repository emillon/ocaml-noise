type t =
  | Chacha_poly
  | AES_GCM
[@@deriving eq,show]

val of_string : string -> (t, string) result

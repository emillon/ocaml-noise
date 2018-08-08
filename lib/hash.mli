type t =
  | SHA256
[@@deriving eq,show]

val of_string : string -> (t, string) result

(** [HASHLEN] *)
val len : t -> int

type t =
  | SHA256
  | SHA512
  | BLAKE2s
  | BLAKE2b
[@@deriving eq, show]

val of_string : string -> (t, string) result

val len : t -> int
(** [HASHLEN] *)

val hash : t -> Cstruct.t -> Cstruct.t

val hmac : t -> key:Cstruct.t -> Cstruct.t -> Cstruct.t

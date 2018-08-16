type t
[@@deriving eq]

val pp : Format.formatter -> t -> unit

val bytes : t -> Cstruct.t

val of_bytes : Cstruct.t -> t

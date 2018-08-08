type t = Cstruct.t
[@@deriving eq,of_yojson]

val pp : Format.formatter -> t -> unit

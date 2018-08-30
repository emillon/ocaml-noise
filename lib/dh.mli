type t = Curve_25519 [@@deriving eq, show]

val of_string : string -> (t, string) result

val len : t -> int
(** The DHLEN constant for this algorithm (in bytes). *)

val key_exchange : t -> priv:Private_key.t -> pub:Public_key.t -> Cstruct.t

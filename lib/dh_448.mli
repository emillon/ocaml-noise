val key_exchange : priv:Private_key.t -> pub:Public_key.t -> Cstruct.t

val corresponds : priv:Private_key.t -> pub:Public_key.t -> bool

val public_key : Private_key.t -> Public_key.t

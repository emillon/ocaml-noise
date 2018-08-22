val scalar_mult :
  pub:Cstruct.t ->
  priv:Cstruct.t ->
  Cstruct.t

exception Wrong_key_size

val poly1305 :
  key:Cstruct.t ->
  Cstruct.t ->
  Cstruct.t

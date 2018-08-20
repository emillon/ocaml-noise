type t

val create :
  Hash.t ->
  Dh.t ->
  Cstruct.t ->
  t

val mix_hash : t -> Cstruct.t -> t

val mix_key : t -> Cstruct.t -> t * Private_key.t

val h : t -> Cstruct.t

val split : t -> Cipher_state.t * Cipher_state.t

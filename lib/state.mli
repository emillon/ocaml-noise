type t

val make :
  name:string ->
  hash:Hash.t ->
  dh:Dh.t ->
  cipher:Cipher.t ->
  s:Private_key.t option ->
  rs:Public_key.t option ->
  e:Private_key.t option ->
  t

val e : t -> Private_key.t option
val e_pub : t -> Public_key.t option
val re : t -> Public_key.t option
val set_re : t -> Public_key.t -> (t, string) result
val s : t -> Private_key.t option
val s_pub : t -> Public_key.t option
val rs : t -> Public_key.t option
val set_rs : t -> Public_key.t -> (t, string) result

val mix_hash : t -> Cstruct.t -> t

val mix_dh_key :
  t ->
  priv:Private_key.t ->
  pub:Public_key.t ->
  t

val decrypt_and_hash :
  t ->
  Cstruct.t ->
  (t * Cstruct.t, string) result

val encrypt_and_hash :
  t ->
  Cstruct.t ->
  (t * Cstruct.t, string) result

val handshake_hash : t -> Cstruct.t option

val split_dh :
  t ->
  Cstruct.t ->
  Public_key.t * Cstruct.t

module One_way_transport : sig
  val setup : t -> t

  val receive :
    t ->
    Cstruct.t ->
    (t * Cstruct.t, string) result

  val send :
    t ->
    Cstruct.t ->
    (t * Cstruct.t, string) result
end

type t

val make :
  name:string ->
  pattern:Pattern.t ->
  is_initiator:bool ->
  hash:Hash.t ->
  dh:Dh.t ->
  cipher:Cipher.t ->
  s:Private_key.t option ->
  rs:Public_key.t option ->
  e:Private_key.t option ->
  t

val e_pub : t -> Public_key.t option
val set_re : t -> Public_key.t -> (t, string) result
val s_pub : t -> Public_key.t option
val set_rs : t -> Public_key.t -> (t, string) result
val is_initiator : t -> bool
val pattern : t -> Pattern.t

type key_type =
  | Static
  | Ephemeral

val mix_hash : t -> Cstruct.t -> t

val mix_dh_key :
  t ->
  local:key_type ->
  remote:key_type ->
  (t, string) result

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

type state =
  | Handshake_not_done
  | One_way_transport

val state : t -> state

val pop_handshake_step : t -> (t * Pattern.step list, string) result

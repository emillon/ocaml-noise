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
  ?clear:bool ->
  t ->
  Cstruct.t ->
  Public_key.t * Cstruct.t

val setup_transport : t -> t

val receive_transport :
  t ->
  Cstruct.t ->
  (t * Cstruct.t, string) result

val send_transport :
  t ->
  Cstruct.t ->
  (t * Cstruct.t, string) result

type state =
  | Handshake_step of Pattern.step list * bool
  | Transport

val next : t -> t * state

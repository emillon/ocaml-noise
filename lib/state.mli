(** [HandshakeState] as defined in v34 5.3. *)

type t

val make :
     name:string
  -> pattern:Pattern.t
  -> is_initiator:bool
  -> hash:Hash.t
  -> dh:Dh.t
  -> cipher:Cipher.t
  -> s:Private_key.t option
  -> rs:Public_key.t option
  -> e:Private_key.t option
  -> psk:Cstruct.t option
  -> t

val e_pub : t -> Public_key.t option
(** The public key corresponding to [e]. *)

val set_re : t -> Public_key.t -> (t, string) result
(** Set [re], returning an error if was set before. *)

val s_pub : t -> Public_key.t option
(** The public key corresponding to [s]. *)

val set_rs : t -> Public_key.t -> (t, string) result
(** Set [rs], returning an error if was set before. *)

val is_initiator : t -> bool

val pattern : t -> Pattern.t

type key_type =
  | Static
  | Ephemeral

val mix_hash : t -> Cstruct.t -> t
(** Delegate [mix_hash] on the underlying [Symmetric_state.t]. *)

val mix_hash_and_psk : t -> Public_key.t -> t
(** Call [mix_hash], and if a PSK is used, call [mix_key] as well. *)

val mix_key : t -> Cstruct.t -> t
(** Call [mix_key] on the underlying [Symmetric_state.t] and initialize the
    [Cipher_state.t] with the result. *)

val mix_dh_key : t -> local:key_type -> remote:key_type -> (t, string) result
(** Perform a key exchange using the [local] and [remote] key types, and call
    [mix_key] using the result. *)

val mix_key_and_hash_psk : t -> (t, string) result
(** Call [Symmetric_state.mix_key_and_hash] with the PSK. *)

val decrypt_and_hash : t -> Cstruct.t -> (t * Cstruct.t, string) result

val encrypt_and_hash : t -> Cstruct.t -> (t * Cstruct.t, string) result

val handshake_hash : t -> Cstruct.t option
(** Get the handshake hash, if the handshake is over. *)

val split_dh : ?clear:bool -> t -> Cstruct.t -> Public_key.t * Cstruct.t
(** Extract a DH key at the beginning of the specified buffer.
    The key size depends on whether it is expected to be encrypted or in clear.
    - if [clear] is [true] (it defaults to [false]), assume it is clear
    - otherwise, depends on [Cipher_state.has_key]
    *)

val setup_transport : t -> t
(** Call [Symmetric_state.split] and setup a one-way or two-way transport
    depending on the pattern. *)

val receive_transport : t -> Cstruct.t -> (t * Cstruct.t, string) result
(** Receive a message, based on the configured transport. *)

val send_transport : t -> Cstruct.t -> (t * Cstruct.t, string) result
(** Send a message, based on the configured transport. *)

type state =
  | Handshake_step of Pattern.step list * bool
      (** Next steps, and is it the last message *)
  | Transport  (** Handshake is over *)

val next : t -> t * state
(** Determine the next step, "popping" the next list of handshake steps. *)

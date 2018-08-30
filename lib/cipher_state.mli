(** The [CipherState] as defined in v34 5.1.
    It is represented a bit differently, since the [n] and [k] values only make
    sense for the case when a key is configured and not depleted.
*)

type t [@@deriving eq, show]

val empty : t
(** No key is set. *)

val create : ?unsafe_nonce:int64 -> Private_key.t -> t
(** Set a key. This sets a nonce to [0L]. [unsafe_nonce] is only used for
    testing. *)

val depleted : t
(** When a key has been used too many times, we arrive at this state, which
    signals an error when trying to encrypt or decrypt. *)

val with_ :
     t
  -> (key:Private_key.t -> nonce:int64 -> 'a -> ('a, string) result)
  -> 'a
  -> (t * 'a, string) result
(** Pass the unwrapped state to a continuation.
    - if the state is [empty], return the state and ['a] parameter, both
    unchanged.
    (if there is no key, encryption/decryption return the plaintext)
    - if a key is set, call the continuation with the key and nonce, and return
    the same state with the nonce incremented (or [depleted]), and the result
    of the continuation.
    - if the state is [depleted], return an error.
*)

val has_key : t -> bool
(** Is it possible to use this to encrypt or decrypt? *)

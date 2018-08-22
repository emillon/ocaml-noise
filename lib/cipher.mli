type t =
  | AES_GCM
  | Chacha_poly
[@@deriving eq,show]

val of_string : string -> (t, string) result

val encrypt_with_ad :
  t ->
  key:Private_key.t ->
  nonce:int64 ->
  ad:Cstruct.t ->
  Cstruct.t ->
  (Cstruct.t, string) result

val decrypt_with_ad :
  t ->
  key:Private_key.t ->
  nonce:int64 ->
  ad:Cstruct.t ->
  Cstruct.t ->
  (Cstruct.t, string) result

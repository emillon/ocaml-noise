val encrypt_with_ad :
  key:Private_key.t ->
  nonce:int64 ->
  ad:Cstruct.t ->
  Cstruct.t ->
  (Cstruct.t, string) result

val encrypt_with_ad_low :
  key:Private_key.t ->
  fixed:Cstruct.t ->
  iv:Cstruct.t ->
  ad:Cstruct.t ->
  Cstruct.t ->
  (Cstruct.t * Cstruct.t, string) result

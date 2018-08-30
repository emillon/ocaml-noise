val iv : nonce:int64 -> Cstruct.t

val encrypt_with_ad :
     key:Private_key.t
  -> nonce:int64
  -> ad:Cstruct.t
  -> Cstruct.t
  -> (Cstruct.t, string) result

val decrypt_with_ad :
     key:Private_key.t
  -> nonce:int64
  -> ad:Cstruct.t
  -> Cstruct.t
  -> (Cstruct.t, string) result

val hkdf2 :
     hmac:(key:Cstruct.t -> Cstruct.t -> Cstruct.t)
  -> salt:Cstruct.t
  -> ikm:Cstruct.t
  -> Cstruct.t * Cstruct.t

val hkdf3 :
     hmac:(key:Cstruct.t -> Cstruct.t -> Cstruct.t)
  -> salt:Cstruct.t
  -> ikm:Cstruct.t
  -> Cstruct.t * Cstruct.t * Cstruct.t

val extract :
     hmac:(key:Cstruct.t -> Cstruct.t -> Cstruct.t)
  -> salt:Cstruct.t
  -> ikm:Cstruct.t
  -> Cstruct.t

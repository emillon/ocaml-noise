val hmac :
  block_len:int ->
  (Cstruct.t -> Cstruct.t) ->
  key:Cstruct.t ->
  Cstruct.t ->
  Cstruct.t

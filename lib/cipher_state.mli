type t
[@@deriving eq,show]

val empty : t

val create :
  ?unsafe_nonce:int64 ->
  Private_key.t ->
  t

val depleted : t

val with_ :
  t ->
  ( key:Private_key.t ->
    nonce:int64 ->
    'a ->
    ('a, string) result
  ) ->
  'a ->
  (t * 'a, string) result

val has_key : t -> bool

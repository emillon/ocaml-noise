type t =
  | Empty
  | Ready of
    { key : Private_key.t
    ; nonce : int64
    }
  | Depleted
[@@deriving eq,show]

val create :
  Private_key.t ->
  t

val incr_nonce : t -> t

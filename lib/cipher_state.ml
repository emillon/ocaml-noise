type t =
  | Empty
  | Ready of
    { key : Private_key.t
    ; nonce : int64
    }
  | Depleted
[@@deriving eq,show]

let create key =
  Ready
    { key
    ; nonce = 0L
    }

let incr_nonce = function
  | Empty -> Empty
  | Ready params ->
    let new_nonce = Int64.succ params.nonce in
    if new_nonce = 0xff_ff_ff_ff_ff_ff_ff_ffL then
      Depleted
    else
      Ready { params with nonce = new_nonce }
  | Depleted -> Depleted

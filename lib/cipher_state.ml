open Util

type t =
  | Empty
  | Ready of {key : Private_key.t; nonce : int64}
  | Depleted
[@@deriving eq, show]

let empty = Empty

let create ?unsafe_nonce:(nonce = 0L) key = Ready {key; nonce}

let depleted = Depleted

let with_ t f x =
  match t with
  | Empty ->
      Ok (t, x)
  | Ready params ->
      let%map r = f ~key:params.key ~nonce:params.nonce x in
      let new_cs =
        let new_nonce = Int64.succ params.nonce in
        if new_nonce = 0xff_ff_ff_ff_ff_ff_ff_ffL then Depleted
        else Ready {params with nonce = new_nonce}
      in
      (new_cs, r)
  | Depleted ->
      Error "Nonce depleted"


let has_key = function
  | Empty ->
      false
  | Ready _ ->
      true
  | Depleted ->
      false

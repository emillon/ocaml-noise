type t = Curve_25519 [@@deriving eq, show]

let of_string = function
  | "25519" ->
      Ok Curve_25519
  | s ->
      Printf.ksprintf (fun e -> Error e) "Dh.of_string: %s" s

let len = function
  | Curve_25519 ->
      32

let key_exchange = function
  | Curve_25519 ->
      Dh_25519.key_exchange

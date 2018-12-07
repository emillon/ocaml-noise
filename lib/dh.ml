type t =
  | Curve_25519
  | Curve_448
[@@deriving eq, show]

let of_string = function
  | "25519" ->
      Ok Curve_25519
  | "448" ->
      Ok Curve_448
  | s ->
      Printf.ksprintf (fun e -> Error e) "Dh.of_string: %s" s

let len = function
  | Curve_25519 ->
      32
  | Curve_448 ->
      56

let key_exchange = function
  | Curve_25519 ->
      Dh_25519.key_exchange
  | Curve_448 ->
      Dh_448.key_exchange

let public_key = function
  | Curve_25519 ->
      Dh_25519.public_key
  | Curve_448 ->
      Dh_448.public_key

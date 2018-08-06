type t =
  | Curve_25519
  | Curve_448
[@@deriving eq,show]

let of_string = function
  | "25519" -> Ok Curve_25519
  | "448" -> Ok Curve_448
  | s -> Printf.ksprintf (fun e -> Error e) "Dh.of_string: %s" s

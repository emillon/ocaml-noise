type t =
  | N
  | X
  | K
  | NN
  | NK
  | NX
  | XN
  | XK
  | XX
  | KN
  | KK
  | KX
  | IN
  | IK
  | IX
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "X" -> Ok X
  | "K" -> Ok K
  | "NN" -> Ok NN
  | "NK" -> Ok NK
  | "NX" -> Ok NX
  | "XN" -> Ok XN
  | "XK" -> Ok XK
  | "XX" -> Ok XX
  | "KN" -> Ok KN
  | "KK" -> Ok KK
  | "KX" -> Ok KX
  | "IN" -> Ok IN
  | "IK" -> Ok IK
  | "IX" -> Ok IX
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

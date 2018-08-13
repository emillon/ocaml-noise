type t =
  | N
  | K
  | X
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | "X" -> Ok X
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

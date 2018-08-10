type t =
  | N
  | K
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

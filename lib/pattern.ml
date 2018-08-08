type t =
  | N
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

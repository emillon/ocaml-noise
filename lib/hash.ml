type t =
  | SHA256
[@@deriving eq,show]

let of_string = function
  | "SHA256" -> Ok SHA256
  | s -> Printf.ksprintf (fun e -> Error e) "Hash.of_string: %s" s

let len = function
  | SHA256 -> 32

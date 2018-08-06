type t =
  | BLAKE2s
  | BLAKE2b
  | SHA256
  | SHA512
[@@deriving eq,show]

let of_string = function
  | "BLAKE2s" -> Ok BLAKE2s
  | "BLAKE2b" -> Ok BLAKE2b
  | "SHA256" -> Ok SHA256
  | "SHA512" -> Ok SHA512
  | s -> Printf.ksprintf (fun e -> Error e) "Hash.of_string: %s" s

type t =
  | SHA256
  | SHA512
[@@deriving eq,show]

let of_string = function
  | "SHA256" -> Ok SHA256
  | "SHA512" -> Ok SHA512
  | s -> Printf.ksprintf (fun e -> Error e) "Hash.of_string: %s" s

let len = function
  | SHA256 -> 32
  | SHA512 -> 64

let hash = function
  | SHA256 -> Hash_sha256.hash
  | SHA512 -> Hash_sha512.hash

let hmac = function
  | SHA256 -> Hash_sha256.hmac
  | SHA512 -> Hash_sha512.hmac

type t =
  | SHA256
  | SHA512
  | BLAKE2s
  | BLAKE2b
[@@deriving eq,show]

let of_string = function
  | "SHA256" -> Ok SHA256
  | "SHA512" -> Ok SHA512
  | "BLAKE2s" -> Ok BLAKE2s
  | "BLAKE2b" -> Ok BLAKE2b
  | s -> Printf.ksprintf (fun e -> Error e) "Hash.of_string: %s" s

let len = function
  | SHA256 -> 32
  | SHA512 -> 64
  | BLAKE2s -> 32
  | BLAKE2b -> 64

let hash = function
  | SHA256 -> Hash_sha256.hash
  | SHA512 -> Hash_sha512.hash
  | BLAKE2s -> Hash_blake2s.hash
  | BLAKE2b -> Hash_blake2b.hash

let hmac = function
  | SHA256 -> Hash_sha256.hmac
  | SHA512 -> Hash_sha512.hmac
  | BLAKE2s -> Hash_blake2s.hmac
  | BLAKE2b -> Hash_blake2b.hmac

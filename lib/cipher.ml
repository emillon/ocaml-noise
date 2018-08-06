type t =
  | Chacha_poly
  | AES_GCM
[@@deriving eq,show]

let of_string = function
  | "ChaChaPoly" -> Ok Chacha_poly
  | "AESGCM" -> Ok AES_GCM
  | s -> Printf.ksprintf (fun e -> Error e) "Cipher.of_string: %s" s

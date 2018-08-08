type t =
  | AES_GCM
[@@deriving eq,show]

let of_string = function
  | "AESGCM" -> Ok AES_GCM
  | s -> Printf.ksprintf (fun e -> Error e) "Cipher.of_string: %s" s

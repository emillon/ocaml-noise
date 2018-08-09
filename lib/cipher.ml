type t =
  | AES_GCM
[@@deriving eq,show]

let of_string = function
  | "AESGCM" -> Ok AES_GCM
  | s -> Printf.ksprintf (fun e -> Error e) "Cipher.of_string: %s" s

let encrypt_with_ad = function
  | AES_GCM -> Cipher_aes_gcm.encrypt_with_ad

let decrypt_with_ad = function
  | AES_GCM -> Cipher_aes_gcm.decrypt_with_ad

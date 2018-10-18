type t =
  | SHA256
  | SHA512
  | BLAKE2s
  | BLAKE2b
[@@deriving eq, show]

let of_string = function
  | "SHA256" ->
      Ok SHA256
  | "SHA512" ->
      Ok SHA512
  | "BLAKE2s" ->
      Ok BLAKE2s
  | "BLAKE2b" ->
      Ok BLAKE2b
  | s ->
      Printf.ksprintf (fun e -> Error e) "Hash.of_string: %s" s

let len = function
  | SHA256 ->
      32
  | SHA512 ->
      64
  | BLAKE2s ->
      32
  | BLAKE2b ->
      64

module type DIGESTIF = sig
  type t

  val to_raw_string : t -> string

  val digest_string : ?off:int -> ?len:int -> string -> t

  val hmac_string : key:string -> ?off:int -> ?len:int -> string -> t
end

let digestif : t -> (module DIGESTIF) = function
  | SHA256 ->
      (module Digestif.SHA256)
  | SHA512 ->
      (module Digestif.SHA512)
  | BLAKE2s ->
      (module Digestif.BLAKE2S)
  | BLAKE2b ->
      (module Digestif.BLAKE2B)

let hash t data =
  let (module D) = digestif t in
  Cstruct.to_string data
  |> D.digest_string
  |> D.to_raw_string
  |> Cstruct.of_string

let hmac t ~key data =
  let (module D) = digestif t in
  let string_key = Cstruct.to_string key in
  Cstruct.to_string data
  |> D.hmac_string ~key:string_key
  |> D.to_raw_string
  |> Cstruct.of_string

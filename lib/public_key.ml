type t = Public of Cstruct.t
[@@deriving eq]

let pp fmt (Public cs) =
  Format.fprintf fmt
    "<public key:@,%a>"
    Cstruct.hexdump_pp cs

let bytes (Public cs) = cs

let of_bytes cs = Public cs

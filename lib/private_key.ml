type t = Private of Cstruct.t
[@@deriving eq]

let pp fmt _ =
  Format.pp_print_string fmt "<private key>"

let bytes (Private cs) = cs

let of_bytes cs = Private cs

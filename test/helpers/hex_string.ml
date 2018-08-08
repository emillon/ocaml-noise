type t = Cstruct.t
[@@deriving eq]

let of_yojson json =
  let open Ppx_deriving_yojson_runtime in
  [%of_yojson: string] json >|= fun s ->
  Hex.to_cstruct (`Hex s)

let pp fmt cstruct =
  let `Hex s = Hex.of_cstruct cstruct in
  Format.pp_print_string fmt s

open OUnit2

module Pattern = struct
  type t = Noise.Pattern.t

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    [%of_yojson: string] json >>= Noise.Pattern.of_string

  let supported = function
    | _ -> false
end

type test_vector =
  { name : string
  ; pattern : Pattern.t
  ; dh : string
  ; cipher: string
  ; hash : string
  ; init_prologue : string
  ; init_ephemeral : string
  ; init_remote_static : string option [@default None]
  ; resp_prologue : string
  ; resp_static : string option [@default None]
  ; messages : Yojson.Safe.json list
  ; handshake_hash : string
  ; init_psk : string option [@default None]
  ; init_static : string option [@default None]
  ; resp_ephemeral : string option [@default None]
  ; resp_psk : string option [@default None]
  ; resp_remote_static : string option [@default None]
  }
[@@deriving of_yojson]

type test_vector_file =
  { vectors : test_vector list
  }
[@@deriving of_yojson]

let build_test_case n vector =
  string_of_int n >:: fun _ctxt ->
    let pattern = vector.pattern in
    let msg =
      Printf.sprintf
        "Pattern %s is not implemented"
        (Noise.Pattern.show pattern)
    in
    skip_if
      (not (Pattern.supported pattern))
      msg

let run path =
  let json = Yojson.Safe.from_file path in
  match test_vector_file_of_yojson json with
  | Ok { vectors } -> path >::: List.mapi build_test_case vectors
  | Error e -> failwith e

let suite =
  "noise-c test vectors" >:::
  [ run "noise-c-basic.txt"
  ]

let () =
  run_test_tt_main suite

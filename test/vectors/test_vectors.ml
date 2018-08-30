open OUnit2
open Noise.Util

let err_printf fmt =
  Printf.ksprintf
    (fun e -> Error e)
    fmt

let unwrap what x =
  match x with
  | Ok y -> Ok y
  | Error s ->
    err_printf
      "Unknown %s: %s"
      what
      s

let of_yojson_string what of_string json =
  let%map s = [%of_yojson: string] json in
  match of_string s with
  | Ok _ as r -> r
  | Error e ->
    err_printf
      "Unknown %s: %s"
      what
      e

type pattern = (Noise.Pattern.t, string) result
let pattern_of_yojson = of_yojson_string "pattern" Noise.Pattern.of_string
type dh = (Noise.Dh.t, string) result
let dh_of_yojson = of_yojson_string "dh" Noise.Dh.of_string
type cipher = (Noise.Cipher.t, string) result
let cipher_of_yojson = of_yojson_string "cipher" Noise.Cipher.of_string
type hash = (Noise.Hash.t, string) result
let hash_of_yojson = of_yojson_string "hash" Noise.Hash.of_string

type message =
  { ciphertext : Test_helpers.Hex_string.t
  ; payload : Test_helpers.Hex_string.t
  }
[@@deriving of_yojson]

module Public_key = struct
  type t = Noise.Public_key.t

  let of_yojson json =
    let%map r = [%of_yojson: Test_helpers.Hex_string.t] json in
    Noise.Public_key.of_bytes r
end

module Private_key = struct
  type t = Noise.Private_key.t

  let of_yojson json =
    let%map r = [%of_yojson: Test_helpers.Hex_string.t] json in
    Noise.Private_key.of_bytes r
end

module Test_vector = struct
  type repr =
    { name : string option [@default None]
    ; protocol_name : string option [@default None]
    ; pattern : pattern option [@default None]
    ; dh : dh option [@default None]
    ; cipher: cipher option [@default None]
    ; hash : hash option [@default None]
    ; init_prologue : string
    ; init_ephemeral : Private_key.t
    ; init_remote_static : Public_key.t option [@default None]
    ; resp_prologue : Test_helpers.Hex_string.t
    ; resp_static : Private_key.t option [@default None]
    ; messages : message list
    ; handshake_hash : Test_helpers.Hex_string.t
    ; init_psk : Test_helpers.Hex_string.t option [@default None]
    ; init_static : Private_key.t option [@default None]
    ; resp_ephemeral : Private_key.t option [@default None]
    ; resp_psk : Test_helpers.Hex_string.t option [@default None]
    ; resp_remote_static : Public_key.t option [@default None]
    ; init_psks : Test_helpers.Hex_string.t list option [@default None]
    ; resp_psks : Test_helpers.Hex_string.t list option [@default None]
    }
  [@@deriving of_yojson]

  type t =
    { name : string
    ; pattern : pattern
    ; dh : dh
    ; cipher: cipher
    ; hash : hash
    ; init_prologue : string
    ; init_ephemeral : Private_key.t
    ; init_remote_static : Public_key.t option
    ; resp_prologue : Test_helpers.Hex_string.t
    ; resp_static : Private_key.t option
    ; messages : message list
    ; handshake_hash : Test_helpers.Hex_string.t
    ; psk : Test_helpers.Hex_string.t option
    ; init_static : Private_key.t option
    ; resp_ephemeral : Private_key.t option
    ; resp_remote_static : Public_key.t option
    }

  let name_of_repr (repr:repr) =
    match repr.name, repr.protocol_name with
    | None, None
      ->
      Error "no name"
    | Some n, None
    | None, Some n
      ->
      Ok n
    | Some _, Some _
      ->
      Error "name and protocol_name are set"

  let parse_parameters name =
    match String.split_on_char '_' name with
    | ["Noise"; pattern; dh; cipher; hash] ->
      Ok (pattern, dh, cipher, hash)
    | _ ->
      Error "Cannot parse parameters"

  let hash_of_repr (repr:repr) name =
    match repr.hash with
    | Some h -> Ok h
    | None ->
      let%map (_, _, _, hash_name) = parse_parameters name in
      Noise.Hash.of_string hash_name

  let cipher_of_repr (repr:repr) name =
    match repr.cipher with
    | Some x -> Ok x
    | None ->
      let%map (_, _, cipher_name, _) = parse_parameters name in
      Noise.Cipher.of_string cipher_name

  let dh_of_repr (repr:repr) name =
    match repr.dh with
    | Some x -> Ok x
    | None ->
      let%map (_, dh_name, _, _) = parse_parameters name in
      Noise.Dh.of_string dh_name

  let pattern_of_repr (repr:repr) name =
    match repr.pattern with
    | Some x -> Ok x
    | None ->
      let%map (pattern_name, _, _, _) = parse_parameters name in
      Noise.Pattern.of_string pattern_name

  let wrap_error f json =
    match f json with
    | Ok _ as x -> x
    | Error e ->
      err_printf
        "Got error %s while parsing: %s"
        e
        (Yojson.Safe.pretty_to_string json)

  let psk_of_repr (repr:repr) =
    let from_psk =
      match repr.init_psk, repr.resp_psk with
      | Some a, Some b when Cstruct.equal a b
        ->
        Ok (Some a)
      | None, None
        ->
        Ok None
      | Some _, None
      | None, Some _
      | Some _, Some _
        ->
        Error "from_psk"
    in
    let from_psks =
      match repr.init_psks, repr.resp_psks with
      | Some [a], Some [b] when Cstruct.equal a b
        ->
        Ok (Some a)
      | None, None
        ->
        Ok None
      | Some _, None
      | None, Some _
      | Some _, Some _
        ->
        Error "from_psks"
    in
    let%bind from_psk = from_psk in (* XXX bind above *)
    let%bind from_psks = from_psks in
    match from_psk, from_psks with
    | None, None
      ->
      Ok None
    | None, Some a
    | Some a, None
      ->
      Ok (Some a)
    | Some _, Some _
      ->
      Error "psk_of_repr"

  let of_yojson json =
    let%bind repr = wrap_error repr_of_yojson json in
    let%bind psk = psk_of_repr repr in
    let%bind name = name_of_repr repr in
    let%bind hash = hash_of_repr repr name in
    let%bind cipher = cipher_of_repr repr name in
    let%bind dh = dh_of_repr repr name in
    let%map pattern = pattern_of_repr repr name in
    { name
    ; pattern
    ; dh
    ; cipher
    ; hash
    ; init_prologue = repr.init_prologue
    ; init_ephemeral = repr.init_ephemeral
    ; init_remote_static = repr.init_remote_static
    ; resp_prologue = repr.resp_prologue
    ; resp_static = repr.resp_static
    ; messages = repr.messages
    ; handshake_hash = repr.handshake_hash
    ; psk
    ; init_static = repr.init_static
    ; resp_ephemeral = repr.resp_ephemeral
    ; resp_remote_static = repr.resp_remote_static
    }
end

type test_vector_file =
  { vectors : Test_vector.t list
  }
[@@deriving of_yojson]

let check_prefix s =
  let expected = "Noise_" in
  let start = String.sub s 0 (String.length expected) in
  if String.equal start expected then
    Ok ()
  else
    Error "Wrong prefix"

let params (vector:Test_vector.t) =
  let%bind () = check_prefix vector.name in
  let%bind pattern = unwrap "pattern" vector.pattern in
  let%bind dh = unwrap "DH" vector.dh in
  let%bind cipher = unwrap "cipher" vector.cipher in
  let%map hash = unwrap "hash" vector.hash in
  (pattern, dh, cipher, hash)

let get_result_exn msg = function
  | Ok x -> x
  | Error e -> Printf.ksprintf invalid_arg "get_result_exn: %s (%s)" msg e

let check_transport_message ~ctxt initiator responder message n =
  let (new_resp, recovered_plaintext) =
    get_result_exn
      "transport message, responder"
      ( Noise.State.receive_transport
          responder
          message.ciphertext
      )
  in
  assert_equal
    ~ctxt
    ~cmp:[%eq: Test_helpers.Hex_string.t]
    ~printer:[%show: Test_helpers.Hex_string.t]
    ~msg:(Printf.sprintf "Transport message #%d decryption" n)
    message.payload
    recovered_plaintext;
  let (new_init, generated_ciphertext) =
    get_result_exn "transport 1, sender"
      ( Noise.State.send_transport
          initiator
          message.payload
      )
  in
  assert_equal
    ~ctxt
    ~cmp:[%eq: Test_helpers.Hex_string.t]
    ~printer:[%show: Test_helpers.Hex_string.t]
    ~msg:(Printf.sprintf "Transport message #%d encryption" n)
    message.ciphertext
    generated_ciphertext;
  (new_init, new_resp)

let concat_some a b =
  match a, b with
  | None, None -> []
  | Some sa, None -> [sa]
  | None, Some sb -> [sb]
  | Some sa, Some sb -> [sa; sb]

let make_responder_from_vector pattern dh cipher hash (vector:Test_vector.t) =
  let e = vector.resp_ephemeral in
  let s = vector.resp_static in
  let static_pub = vector.init_remote_static in
  let rs = vector.resp_remote_static in
  let psk = vector.psk in
  Noise.State.make
    ~name:vector.name
    ~pattern
    ~is_initiator:false
    ~s
    ~rs
    ~e
    ~dh
    ~cipher
    ~hash
    ~psk
  |> Noise.Protocol.initialize
    ~prologue:vector.resp_prologue
    ~public_keys:(concat_some rs static_pub)

let make_initiator_from_vector pattern dh cipher hash (vector:Test_vector.t) =
  let rs = vector.init_remote_static in
  let e = vector.init_ephemeral in
  let s = vector.init_static in
  let s_pub = vector.resp_remote_static in
  let psk = vector.psk in
  Noise.State.make
    ~name:vector.name
    ~is_initiator:true
    ~pattern
    ~s
    ~rs
    ~e:(Some e)
    ~dh
    ~cipher
    ~hash
    ~psk
  |> Noise.Protocol.initialize
    ~prologue:vector.resp_prologue
    ~public_keys:(concat_some s_pub rs)

let post_handshake pattern init0 resp0 msgs =
  match Noise.Pattern.all_steps pattern, msgs with
  | [_], msg1::msgs ->
    let%bind (init1, _) = Noise.Protocol.write_message init0 msg1.payload in
    let%map (resp1, _) = Noise.Protocol.read_message resp0 msg1.ciphertext in
    (init1, resp1, msgs)
  | [_; _], msg1::msg2::msgs ->
    let%bind (init1, _) = Noise.Protocol.write_message init0 msg1.payload in
    let%bind (resp1, _) = Noise.Protocol.read_message resp0 msg1.ciphertext in
    let%bind (resp2, _) = Noise.Protocol.write_message resp1 msg2.payload in
    let%map (init2, _) = Noise.Protocol.read_message init1 msg2.ciphertext in
    (init2, resp2, msgs)
  | [_; _; _], msg1::msg2::msg3::msgs ->
    let%bind (init1, _) = Noise.Protocol.write_message init0 msg1.payload in
    let%bind (resp1, _) = Noise.Protocol.read_message resp0 msg1.ciphertext in
    let%bind (resp2, _) = Noise.Protocol.write_message resp1 msg2.payload in
    let%bind (init2, _) = Noise.Protocol.read_message init1 msg2.ciphertext in
    let%bind (init3, _) = Noise.Protocol.write_message init2 msg3.payload in
    let%map (resp3, _) = Noise.Protocol.read_message resp2 msg3.ciphertext in
    (resp3, init3, msgs)
  | _ ->
    Error "Wrong number of messages"

let build_test_case (vector:Test_vector.t) =
  vector.name >:: fun ctxt ->
    match params vector with
    | Error e ->
      skip_if true e
    | Ok (pattern, dh, cipher, hash) ->
      let responder = make_responder_from_vector pattern dh cipher hash vector in
      let initiator = make_initiator_from_vector pattern dh cipher hash vector in

      let (initiator_post_handshake, responder_post_handshake, transport_messages) =
        get_result_exn "post_handshake" @@
        post_handshake pattern initiator responder vector.messages
      in
      let initiator_hash =
        Noise.State.handshake_hash initiator_post_handshake
      in
      let responder_hash =
        Noise.State.handshake_hash responder_post_handshake
      in

      assert_equal
        ~ctxt
        ~cmp:[%eq: Test_helpers.Hex_string.t option]
        ~printer:[%show: Test_helpers.Hex_string.t option]
        ~msg:"Handshake hashes should match"
        initiator_hash
        responder_hash;
      assert_equal
        ~cmp:[%eq: Test_helpers.Hex_string.t option]
        ~printer:[%show: Test_helpers.Hex_string.t option]
        ~msg:"Handshake hash should match the vector"
        (Some vector.handshake_hash)
        initiator_hash;

      let flip a b =
        match Noise.Pattern.transport pattern with
        | One_way ->
          (a, b)
        | Two_way ->
          (b, a)
      in
      let _ : Noise.State.t * Noise.State.t * int =
        List.fold_left
          (fun (init, resp, i) message ->
             let (new_init, new_resp) =
               check_transport_message ~ctxt init resp message i
             in
             let (new_init1, new_resp1) = flip new_init new_resp in
             (new_init1, new_resp1, i+1)
          )
          ( initiator_post_handshake
          , responder_post_handshake
          , 1
          )
          transport_messages
      in
      ()

let run path =
  let json = Yojson.Safe.from_file path in
  match test_vector_file_of_yojson json with
  | Ok { vectors } ->
    path >::: List.map build_test_case vectors
  | Error e ->
    Printf.ksprintf
      failwith
      "Cannot parse file %s: %s"
      path e

let suite =
  "noise-c test vectors" >:::
  [ run "noise-c-basic.txt"
  ; run "cacophony.txt"
  ]

let () =
  run_test_tt_main suite

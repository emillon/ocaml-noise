open Util

let handle_ss s =
  State.mix_dh_key
    s
    ~remote:Static
    ~local:Static

type init_handler =
  State.t ->
  (State.t * Cstruct.t, string) result

let compose_init_handlers : init_handler list -> init_handler =
  let rec go msgs s = function
    | [] -> Ok (s, Cstruct.concat (List.rev msgs))
    | hdl::hdls ->
      hdl s >>= fun (new_s, new_msg) ->
      go (new_msg::msgs) new_s hdls
  in
  fun handlers state ->
    go [] state handlers

let init_handler_e n0 =
  match State.e_pub n0 with
  | None ->
    Error "No ephemeral public key"
  | Some epub ->
    let n1 = State.mix_hash n0 (Public_key.bytes epub) in
    Ok (n1, Public_key.bytes epub)

let init_return x = Ok (x, Cstruct.empty)

let init_handler_es n =
  State.mix_dh_key
    n
    ~local:Ephemeral
    ~remote:Static
  >>= init_return

let init_handler_payload payload : init_handler =
  fun n0 ->
    State.encrypt_and_hash n0 payload >>= fun (n1, msg1) ->
    let n2 = State.One_way_transport.setup n1 in
    Ok (n2, msg1)

let init_handler_ss : init_handler =
  fun n ->
    handle_ss n >>= init_return

let init_handler_s : init_handler =
  fun s ->
    match State.s_pub s with
    | None ->
      Error "No static public key"
    | Some s_pub ->
      let plaintext = Public_key.bytes s_pub in
      State.encrypt_and_hash s plaintext

let init_handlers pattern payload =
  match pattern with
  | Pattern.N ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_payload payload
    ]
  | Pattern.K ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_ss
    ; init_handler_payload payload
    ]
  | Pattern.X ->
    [ init_handler_e
    ; init_handler_es
    ; init_handler_s
    ; init_handler_ss
    ; init_handler_payload payload
    ]

let write_message s payload =
  match State.state s with
  | Handshake_not_done ->
    assert (State.is_initiator s);
    let pattern = State.pattern s in
    compose_init_handlers (init_handlers pattern payload) s
  | One_way_transport ->
    State.One_way_transport.send s payload

type resp_handler =
  State.t ->
  Cstruct.t ->
  (State.t * Cstruct.t, string) result

let rec compose_resp_handlers : resp_handler list -> resp_handler =
  fun handlers s msg ->
    match handlers with
    | hdl::hdls ->
      hdl s msg >>= fun (next_s, next_msg) ->
      compose_resp_handlers hdls next_s next_msg
    | [] -> Ok (s, msg)

let responder_handle_es s =
  State.mix_dh_key
    s
    ~remote:Ephemeral
    ~local:Static

let resp_handler_es : resp_handler =
  fun s msg ->
    responder_handle_es s >>= fun new_s ->
    Ok (new_s, msg)

let resp_handler_ss : resp_handler =
  fun s msg ->
    handle_ss s >>= fun new_s ->
    Ok (new_s, msg)

let resp_handler_payload : resp_handler =
  fun s msg ->
    State.decrypt_and_hash s msg >>= fun (new_s, new_msg) ->
    Ok
      ( State.One_way_transport.setup new_s
      , new_msg
      )

let resp_handler_s : resp_handler =
  fun s0 msg ->
    let (temp, new_msg) = State.split_dh s0 msg in
    State.decrypt_and_hash s0 (Public_key.bytes temp) >>= fun (s1, plaintext) ->
    State.set_rs s1 (Public_key.of_bytes plaintext) >>= fun s2 ->
    Ok (s2, new_msg)

let resp_handler_e n0 msg0 =
  let (re, msg1) = State.split_dh n0 msg0 in
  State.set_re n0 re >>= fun n1 ->
  let n2 = State.mix_hash n1 (Public_key.bytes re) in
  Ok (n2, msg1)

let responder_handlers = function
  | Pattern.N ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_payload
    ]
  | Pattern.K ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_ss
    ; resp_handler_payload
    ]
  | Pattern.X ->
    [ resp_handler_e
    ; resp_handler_es
    ; resp_handler_s
    ; resp_handler_ss
    ; resp_handler_payload
    ]

let read_message s =
  match State.state s with
  | Handshake_not_done ->
    assert (not (State.is_initiator s));
    assert (State.handshake_hash s = None);
    let pattern = State.pattern s in
    compose_resp_handlers (responder_handlers pattern) s
  | One_way_transport ->
    State.One_way_transport.receive s

let initialize s ~prologue ~public_keys =
  List.fold_left
    State.mix_hash
    s
    (prologue::List.map Public_key.bytes public_keys)

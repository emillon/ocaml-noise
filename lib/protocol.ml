open Util

let handle_ss s =
  State.mix_dh_key
    s
    ~remote:Static
    ~local:Static

let write_handler_payload payload s0 =
  State.encrypt_and_hash s0 payload >>= fun (s1, msg1) ->
  let s2 = State.One_way_transport.setup s1 in
  Ok (s2, msg1)

let write_handler step s0 =
  let open Pattern in
  let return r =
    r >>| (fun x -> (x, Cstruct.empty))
  in
  match step with
  | E ->
    begin
      match State.e_pub s0 with
      | None ->
        Error "No ephemeral public key"
      | Some epub ->
        let s1 = State.mix_hash s0 (Public_key.bytes epub) in
        Ok (s1, Public_key.bytes epub)
    end
  | ES ->
    return @@
    State.mix_dh_key
      s0
      ~local:Ephemeral
      ~remote:Static
  | S ->
    begin
      match State.s_pub s0 with
      | None ->
        Error "No static public key"
      | Some s_pub ->
        let plaintext = Public_key.bytes s_pub in
        State.encrypt_and_hash s0 plaintext
    end
  | SS ->
    return @@ handle_ss s0

let compose_write_handlers payload state steps =
  let rec go msgs s = function
    | [] -> Ok (s, Cstruct.concat (List.rev msgs))
    | hdl::hdls ->
      hdl s >>= fun (new_s, new_msg) ->
      go (new_msg::msgs) new_s hdls
  in
  let handlers =
    List.map write_handler steps
  in
  let handlers = handlers @ [write_handler_payload payload] in
  go [] state handlers

let write_message s0 payload =
  match State.state s0 with
  | Handshake_not_done ->
    assert (State.is_initiator s0);
    State.pop_handshake_step s0 >>= fun (s1, steps) ->
    compose_write_handlers payload s1 steps
  | One_way_transport ->
    State.One_way_transport.send s0 payload

let read_handler_payload s msg =
  State.decrypt_and_hash s msg >>= fun (new_s, new_msg) ->
  Ok
    ( State.One_way_transport.setup new_s
    , new_msg
    )

let read_handler step s0 msg0 =
  let open Pattern in
  match step with
  | E ->
    let (re, msg1) = State.split_dh s0 msg0 in
    State.set_re s0 re >>= fun s1 ->
    let s2 = State.mix_hash s1 (Public_key.bytes re) in
    Ok (s2, msg1)
  | ES ->
    State.mix_dh_key
      s0
      ~remote:Ephemeral
      ~local:Static
    >>= fun s1 ->
    Ok (s1, msg0)
  | S ->
    let (temp, msg1) = State.split_dh s0 msg0 in
    State.decrypt_and_hash s0 (Public_key.bytes temp) >>= fun (s1, plaintext) ->
    State.set_rs s1 (Public_key.of_bytes plaintext) >>= fun s2 ->
    Ok (s2, msg1)
  | SS ->
    handle_ss s0 >>= fun s1 ->
    Ok (s1, msg0)

let rec compose_read_handlers s steps msg =
  match steps with
  | step::steps ->
    let hdl = read_handler step in
    hdl s msg >>= fun (next_s, next_msg) ->
    compose_read_handlers next_s steps next_msg
  | [] ->
    read_handler_payload s msg

let read_message s0 msg =
  match State.state s0 with
  | Handshake_not_done ->
    assert (not (State.is_initiator s0));
    State.pop_handshake_step s0 >>= fun (s1, steps) ->
    compose_read_handlers s1 steps msg
  | One_way_transport ->
    State.One_way_transport.receive s0 msg

let initialize s ~prologue ~public_keys =
  List.fold_left
    State.mix_hash
    s
    (prologue::List.map Public_key.bytes public_keys)

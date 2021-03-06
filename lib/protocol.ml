open Util

let handle_ss s = State.mix_dh_key s ~remote:Static ~local:Static

let handle_ee s = State.mix_dh_key s ~remote:Ephemeral ~local:Ephemeral

let write_handler_payload payload s0 = State.encrypt_and_hash s0 payload

let write_handler step s0 =
  let open Pattern in
  let return r =
    let%map x = r in
    (x, Cstruct.empty)
  in
  match step with
  | E -> (
    match State.e_pub s0 with
    | None ->
        Error "No ephemeral public key"
    | Some epub ->
        let s1 = State.mix_hash_and_psk s0 epub in
        Ok (s1, Public_key.bytes epub) )
  | ES ->
      let local, remote =
        let open State in
        if is_initiator s0 then (Ephemeral, Static) else (Static, Ephemeral)
      in
      return @@ State.mix_dh_key s0 ~local ~remote
  | SE ->
      let local, remote =
        let open State in
        if is_initiator s0 then (Static, Ephemeral) else (Ephemeral, Static)
      in
      return @@ State.mix_dh_key s0 ~local ~remote
  | S -> (
    match State.s_pub s0 with
    | None ->
        Error "No static public key"
    | Some s_pub ->
        let plaintext = Public_key.bytes s_pub in
        State.encrypt_and_hash s0 plaintext )
  | SS ->
      return @@ handle_ss s0
  | EE ->
      return @@ handle_ee s0
  | PSK ->
      return @@ State.mix_key_and_hash_psk s0

let compose_write_handlers payload state steps =
  let rec go msgs s = function
    | [] ->
        Ok (s, Cstruct.concat (List.rev msgs))
    | hdl :: hdls ->
        let%bind new_s, new_msg = hdl s in
        go (new_msg :: msgs) new_s hdls
  in
  let handlers = List.map write_handler steps in
  let handlers = handlers @ [write_handler_payload payload] in
  go [] state handlers

let apply_transport ~is_last s =
  if is_last then State.setup_transport s else s

let write_message s0 payload =
  let s1, state = State.next s0 in
  match state with
  | Handshake_step (steps, is_last) ->
      let%map s2, ciphertext = compose_write_handlers payload s1 steps in
      let s3 = apply_transport ~is_last s2 in
      (s3, ciphertext)
  | Transport ->
      State.send_transport s1 payload

let read_handler_payload s msg = State.decrypt_and_hash s msg

let read_handler step s0 msg0 =
  let open Pattern in
  match step with
  | E ->
      let re, msg1 = State.split_dh ~clear:true s0 msg0 in
      let%map s1 = State.set_re s0 re in
      let s2 = State.mix_hash_and_psk s1 re in
      (s2, msg1)
  | ES ->
      let local, remote =
        let open State in
        if is_initiator s0 then (Ephemeral, Static) else (Static, Ephemeral)
      in
      let%map s1 = State.mix_dh_key s0 ~remote ~local in
      (s1, msg0)
  | SE ->
      let local, remote =
        let open State in
        if is_initiator s0 then (Static, Ephemeral) else (Ephemeral, Static)
      in
      let%map s1 = State.mix_dh_key s0 ~remote ~local in
      (s1, msg0)
  | S ->
      let temp, msg1 = State.split_dh s0 msg0 in
      let%bind s1, plaintext =
        State.decrypt_and_hash s0 (Public_key.bytes temp)
      in
      let%map s2 = State.set_rs s1 (Public_key.of_bytes plaintext) in
      (s2, msg1)
  | SS ->
      let%map s1 = handle_ss s0 in
      (s1, msg0)
  | EE ->
      let%map s1 = handle_ee s0 in
      (s1, msg0)
  | PSK ->
      let%map s1 = State.mix_key_and_hash_psk s0 in
      (s1, msg0)

let rec compose_read_handlers s steps msg =
  match steps with
  | step :: steps ->
      let hdl = read_handler step in
      let%bind next_s, next_msg = hdl s msg in
      compose_read_handlers next_s steps next_msg
  | [] ->
      read_handler_payload s msg

let read_message s0 msg =
  let s1, state = State.next s0 in
  match state with
  | Handshake_step (steps, is_last) ->
      let%map s2, plaintext = compose_read_handlers s1 steps msg in
      let s3 = apply_transport ~is_last s2 in
      (s3, plaintext)
  | Transport ->
      State.receive_transport s1 msg

let initialize s ~prologue ~public_keys =
  List.fold_left State.mix_hash s
    (prologue :: List.map Public_key.bytes public_keys)

(**
   This is an example of a one-way transport protocol.

   Two processes are started, and after the handshake message is sent, the
   initiator can send messages to the responder.
*)

let dh = Noise.Dh.Curve_25519

let crypto_random_bytes n =
  let ic = Pervasives.open_in_bin "/dev/urandom" in
  let s = Pervasives.really_input_string ic n in
  close_in ic;
  Cstruct.of_string s

let generate_private_key () =
  Noise.Dh.len dh
  |> crypto_random_bytes
  |> Noise.Private_key.of_bytes

let generate_key_pair () =
  let priv = generate_private_key () in
  (Noise.Dh_25519.public_key priv, priv)

let make_state ~is_initiator =
  Noise.State.make
    ~name:"Noise_N_25519_AESGCM_SHA512"
    ~pattern:Noise.Pattern.N
    ~is_initiator
    ~hash:Noise.Hash.SHA512
    ~dh
    ~cipher:Noise.Cipher.AES_GCM
    ~psk:None

exception Noise_protocol_error of string

let to_lwt = function
  | Ok x -> Lwt.return x
  | Error e -> Lwt.fail (Noise_protocol_error e)

let write_message oc state msg =
  let%lwt (new_state, ciphertext) =
    to_lwt (Noise.Protocol.write_message state msg)
  in
  let `Hex hex_line = Hex.of_cstruct ciphertext in
  let%lwt () = Lwt_io.write_line oc hex_line in
  Lwt.return new_state

let read_message ic state =
  let%lwt hex_line = Lwt_io.read_line ic in
  let ciphertext = Hex.to_cstruct (`Hex hex_line) in
  to_lwt @@ Noise.Protocol.read_message state ciphertext

let initiator ~prologue ~rs ~write_chan =
  let write = write_message write_chan in
  let e = generate_private_key () in
  let state0 =
    make_state
      ~rs:(Some rs)
      ~e:(Some e)
      ~s:None
      ~is_initiator:true
    |> Noise.Protocol.initialize
      ~prologue
      ~public_keys:[rs]
  in
  let%lwt state1 = write state0 Cstruct.empty in
  assert (Noise.State.handshake_hash state1 <> None);
  let go state msg = write state @@ Cstruct.of_string msg in
  let msgs =
    [ "Hello"
    ; "Noise"
    ; "Protocol"
    ; "stop"
    ]
  in
  let%lwt (_:Noise.State.t) = Lwt_list.fold_left_s go state1 msgs in
  Lwt.return_unit

let responder ~prologue ~s ~read_chan =
  let read = read_message read_chan in
  let e = generate_private_key () in
  let state0 =
    make_state
      ~is_initiator:false
      ~rs:None
      ~e:(Some e)
      ~s:(Some s)
    |> Noise.Protocol.initialize
      ~prologue
      ~public_keys:[Noise.Dh_25519.public_key s]
  in
  let%lwt (state1, payload) = read state0 in
  assert (Cstruct.length payload = 0);
  assert (Noise.State.handshake_hash state1 <> None);
  let state = ref state1 in
  while%lwt true do
    let%lwt (new_state, cs) = read !state in
    let s = Cstruct.to_string cs in
    if s = "stop" then
      exit 0;
    let%lwt () = Lwt_io.printlf "resp: received %s%!" s in
    state := new_state;
    Lwt.return_unit
  done

let main =
  let (rs, s) = generate_key_pair () in
  let (read_chan, write_chan) = Lwt_io.pipe () in
  let prologue = Cstruct.of_string "some-prologue-data" in
  let%lwt () = Lwt_io.flush_all () in
  match Lwt_unix.fork () with
  | n when n < 0 ->
    failwith "fork"
  | 0 -> initiator ~prologue ~rs ~write_chan
  | _ -> responder ~prologue ~s ~read_chan

let () = Lwt_main.run main

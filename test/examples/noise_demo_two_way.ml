(**
   This is an example of a two-way transport protocol.

   Two processes are started, and after the handshake messages are exchanged,
   the participants can talk to each other securely.
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

let make_state ~is_initiator =
  Noise.State.make
    ~name:"Noise_XX_25519_AESGCM_SHA512"
    ~pattern:Noise.Pattern.XX
    ~is_initiator
    ~hash:Noise.Hash.SHA512
    ~dh
    ~cipher:Noise.Cipher.AES_GCM
    ~rs:None

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

let initiator ~prologue ~read_chan ~write_chan =
  let read = read_message read_chan in
  let write = write_message write_chan in
  let s = generate_private_key () in
  let e = generate_private_key () in
  let state0 =
    make_state
      ~e:(Some e)
      ~s:(Some s)
      ~is_initiator:true
    |> Noise.Protocol.initialize
      ~prologue
      ~public_keys:[]
  in
  let%lwt state1 = write state0 Cstruct.empty in
  let%lwt (state2, _) = read state1 in
  let%lwt state3 = write state2 Cstruct.empty in
  assert (Noise.State.handshake_hash state3 <> None);
  let go state msg =
    let%lwt state_inter = write state @@ Cstruct.of_string msg in
    let%lwt (new_state, response) = read state_inter in
    let%lwt () = Lwt_io.printlf "init: got %s" (Cstruct.to_string response) in
    Lwt.return new_state
  in
  let msgs =
    [ "Hello"
    ; "Noise"
    ; "Protocol"
    ; "stop"
    ]
  in
  let%lwt (_:Noise.State.t) = Lwt_list.fold_left_s go state3 msgs in
  Lwt.return_unit

let responder ~prologue ~read_chan ~write_chan =
  let read = read_message read_chan in
  let write = write_message write_chan in
  let s = generate_private_key () in
  let e = generate_private_key () in
  let state0 =
    make_state
      ~is_initiator:false
      ~e:(Some e)
      ~s:(Some s)
    |> Noise.Protocol.initialize
      ~prologue
      ~public_keys:[]
  in
  let%lwt (state1, _) = read state0 in
  let%lwt state2 = write state1 Cstruct.empty in
  let%lwt (state3, payload) = read state2 in
  assert (Cstruct.len payload = 0);
  assert (Noise.State.handshake_hash state3 <> None);
  let handle s =
    if s = "stop" then
      exit 0;
    Printf.sprintf
      "len(%s) = %d"
      s
      (String.length s)
  in
  let state = ref state3 in
  while%lwt true do
    let%lwt (state_inter, cs) = read !state in
    let%lwt new_state = write state_inter @@ Cstruct.of_string @@ handle @@ Cstruct.to_string cs in
    state := new_state;
    Lwt.return_unit
  done

let main =
  let (r2i_read, r2i_write) = Lwt_io.pipe () in
  let (i2r_read, i2r_write) = Lwt_io.pipe () in
  let prologue = Cstruct.of_string "some-prologue-data" in
  let%lwt () = Lwt_io.flush_all () in
  match Lwt_unix.fork () with
  | n when n < 0 ->
    failwith "fork"
  | 0 ->
    initiator
      ~prologue
      ~read_chan:i2r_read
      ~write_chan:r2i_write
  | _ ->
    responder
      ~prologue
      ~read_chan:r2i_read
      ~write_chan:i2r_write

let () = Lwt_main.run main

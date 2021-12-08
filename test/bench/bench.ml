let crypto_random_bytes n =
  let ic = Stdlib.open_in_bin "/dev/urandom" in
  let s = Stdlib.really_input_string ic n in
  close_in ic;
  Cstruct.of_string s

let random_private_key len =
  Noise.Private_key.of_bytes @@ crypto_random_bytes len

let ensure_ok r =
  match r with
  | Ok _ -> ()
  | Error e -> failwith e

let bench_ciphers () =
  let plaintext = crypto_random_bytes 10_000 in

  let ad = crypto_random_bytes 10 in

  let bench_cipher algo key =
    Noise.Cipher.encrypt_with_ad
      algo
      ~key
      ~nonce:0L
      ~ad
      plaintext
    |> ensure_ok
  in

  let key_aes = random_private_key 16 in
  let key_chacha = random_private_key 32 in

  Benchmark.throughputN 1
    [ ("AES-GCM", bench_cipher Noise.Cipher.AES_GCM, key_aes)
    ; ("ChaChaPoly", bench_cipher Noise.Cipher.Chacha_poly, key_chacha)
    ]

let bench_hashes () =
  let data = crypto_random_bytes 1_000 in

  let bench_hash hash () =
    Noise.Hash.hash hash data
  in

  Benchmark.throughputN 1
    [ ("SHA256", bench_hash Noise.Hash.SHA256, ())
    ; ("SHA512", bench_hash Noise.Hash.SHA512, ())
    ; ("BLAKE2s", bench_hash Noise.Hash.BLAKE2s, ())
    ; ("BLAKE2b", bench_hash Noise.Hash.BLAKE2b, ())
    ]

let bench_dh () =
  let priv = random_private_key 32 in
  let pub = Noise.Dh_25519.public_key @@ random_private_key 32 in

  let bench_dh dh () : Cstruct.t =
    Noise.Dh.key_exchange dh ~priv ~pub
  in

  Benchmark.throughputN 1
    [ ("X25519", bench_dh Noise.Dh.Curve_25519, ())
    ]

let () =
  let open Benchmark.Tree in
  register @@
  "Noise" @>>>
  [ "ciphers" @> lazy (bench_ciphers ())
  ; "hashes" @> lazy (bench_hashes ())
  ; "dh" @> lazy (bench_dh ())
  ]

let () = Benchmark.Tree.run_global ()

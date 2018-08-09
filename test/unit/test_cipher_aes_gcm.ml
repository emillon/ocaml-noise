open OUnit2

let test_iv =
  let test nonce expected ctxt =
    let got = Noise.Cipher_aes_gcm.iv ~nonce in
    let expected = Hex.to_cstruct expected in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t]
      expected
      got
  in
  "iv" >:::
  [ "zeroes" >:: test 0L (`Hex "000000000000000000000000")
  ; "ones" >:: test 0xff_ff_ff_ff_ff_ff_ff_ffL (`Hex "00000000ffffffffffffffff")
  ; "endianness" >:: test 0x01_02_03_04_05_06_07_08L (`Hex "000000000102030405060708")
  ]

module Data = struct
  let plaintext = `Hex "deadbeef"
  let ciphertext = `Hex "a3f07724e1b3940449def6fce7608c8d01c79ec5"
  let key = `Hex "000102030405060708090a0b0c0d0e0f"
  let nonce = 54L
  let ad = `Hex "010203"
end

let test_encrypt_with_ad =
  let test ~key ~nonce ~ad ~plaintext ~expected ctxt =
    let key = Noise.Private_key.of_bytes @@ Hex.to_cstruct key in
    let ad = Hex.to_cstruct ad in
    let plaintext = Hex.to_cstruct plaintext in
    let expected =
      match expected with
      | Ok h -> Ok (Hex.to_cstruct h)
      | Error _ as e -> e
    in
    let got = Noise.Cipher_aes_gcm.encrypt_with_ad ~key ~nonce ~ad plaintext in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Test_helpers.Hex_string.t, string) result]
      ~printer:[%show: (Test_helpers.Hex_string.t, string) result]
      expected
      got
  in
  let open Data in
  "encrypt_with_ad" >:::
  [ "OK" >:: test
    ~key
    ~nonce
    ~ad
    ~plaintext
    ~expected:(Ok ciphertext)
  ; "Wrong key size" >::
    test
    ~key:(`Hex "00")
    ~nonce
    ~ad
    ~plaintext
    ~expected:(Error "Wrong key size")
  ]

let alter_tag h =
  let cs = Hex.to_cstruct h in
  let last_index = Cstruct.len cs - 1 in
  let modify = function
    | 0 -> 1
    | _ -> 0
  in
  Cstruct.get_uint8 cs last_index
  |> modify
  |> Cstruct.set_uint8 cs last_index;
  Hex.of_cstruct cs

let test_decrypt_with_ad =
  let test ~key ~nonce ~ad ~ciphertext ~expected ctxt =
    let key = Noise.Private_key.of_bytes @@ Hex.to_cstruct key in
    let ad = Hex.to_cstruct ad in
    let ciphertext = Hex.to_cstruct ciphertext in
    let expected =
      match expected with
      | Ok h -> Ok (Hex.to_cstruct h)
      | Error _ as e -> e
    in
    let got = Noise.Cipher_aes_gcm.decrypt_with_ad ~key ~nonce ~ad ciphertext in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Test_helpers.Hex_string.t, string) result]
      ~printer:[%show: (Test_helpers.Hex_string.t, string) result]
      expected
      got
  in
  let open Data in
  "decrypt_with_ad" >:::
  [ "OK" >:: test
    ~key
    ~nonce
    ~ad
    ~ciphertext
    ~expected:(Ok plaintext)
  ; "Wrong key size" >:: test
    ~key:(`Hex "00")
    ~nonce
    ~ad
    ~ciphertext
    ~expected:(Error "Wrong key size")
  ; "Ciphertext too short" >:: test
    ~key
    ~nonce
    ~ad
    ~ciphertext:(`Hex "0102")
    ~expected:(Error "Ciphertext is too short")
  ; "Wrong tag" >:: test
    ~key
    ~nonce
    ~ad
    ~ciphertext:(alter_tag ciphertext)
    ~expected:(Error "Wrong tag")
  ]

let suite =
  "Cipher_aes_gcm" >:::
  [ test_iv
  ; test_encrypt_with_ad
  ; test_decrypt_with_ad
  ]

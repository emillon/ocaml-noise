open OUnit2

let hmac_sha1 ~key input =
  let key_string = Cstruct.to_string key in
  let digest = Digestif.SHA1.hmac_string ~key:key_string (Cstruct.to_string input) in
  let hex_digest = Digestif.SHA1.to_hex digest in
  Cstruct.of_hex hex_digest

let hmac_sha256 ~key input =
  let key_string = Cstruct.to_string key in
  let digest = Digestif.SHA256.hmac_string ~key:key_string (Cstruct.to_string input) in
  let hex_digest = Digestif.SHA256.to_hex digest in
  Cstruct.of_hex hex_digest

let test_extract =
  let test ~hmac ~salt ~ikm ~expected ctxt =
    let got =
      Noise.Hkdf.extract
        ~hmac
        ~salt:(Hex.to_cstruct salt)
        ~ikm:(Hex.to_cstruct ikm)
    in
    let expected = Hex.to_cstruct expected in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t]
      expected
      got
  in
  "extract" >:::
  [ "RFC Test Case 1" >::
    test
      ~hmac:hmac_sha256
      ~ikm:(`Hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      ~salt:(`Hex "000102030405060708090a0b0c")
      ~expected:(`Hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
  ; "RFC Test Case 2" >::
    test
      ~hmac:hmac_sha256
      ~ikm:
        ( `Hex
            (String.concat ""
               [ "000102030405060708090a0b0c0d0e0f"
               ; "101112131415161718191a1b1c1d1e1f"
               ; "202122232425262728292a2b2c2d2e2f"
               ; "303132333435363738393a3b3c3d3e3f"
               ; "404142434445464748494a4b4c4d4e4f"
               ]
            )
        )
      ~salt:
        ( `Hex
            (String.concat ""
               [ "606162636465666768696a6b6c6d6e6f"
               ; "707172737475767778797a7b7c7d7e7f"
               ; "808182838485868788898a8b8c8d8e8f"
               ; "909192939495969798999a9b9c9d9e9f"
               ; "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
               ]
            )
        )
        ~expected:(`Hex "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
  ]

let test_hkdf2 =
  let test ~hmac ~ikm ~salt ~expected ctxt =
    let got =
      Noise.Hkdf.hkdf2
        ~hmac
        ~salt:(Hex.to_cstruct salt)
        ~ikm:(Hex.to_cstruct ikm)
    in
    let expected1, expected2 = expected in
    let expected = Hex.to_cstruct expected1, Hex.to_cstruct expected2 in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t * Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t * Test_helpers.Hex_string.t]
      expected
      got
  in
  "hkdf2" >:::
  [ "test vector 7" >::
    test
    ~hmac:hmac_sha1
    ~salt:(`Hex "0000000000000000000000000000000000000000")
    ~ikm:(`Hex "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
    ~expected:
      ( `Hex "2c91117204d745f3500d636a62f64f0ab3bae548"
      , `Hex "aa53d423b0d1f27ebba6f5e5673a081d70cce7ac"
      )
  ]

let suite =
  "HKDF" >:::
  [ test_extract
  ; test_hkdf2
  ]

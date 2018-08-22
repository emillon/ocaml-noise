open OUnit2
open Test_helpers

let of_hexdump hex_lines =
  Hex.to_cstruct (`Hex (String.concat "" hex_lines))

let of_hex hex =
  Hex.to_cstruct (`Hex hex)

let test_encrypt =
  let test ~plaintext ~ad ~key ~iv ~fixed ~expected_ciphertext ~expected_tag
      ctxt =
    let got =
      Noise.Cipher_chacha_poly.encrypt_with_ad_low
        ~ad
        ~key
        ~fixed
        ~iv
        plaintext
    in
    let expected = Ok (expected_ciphertext, expected_tag) in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Hex_string.t * Hex_string.t, string) result]
      ~printer:[%show: (Hex_string.t * Hex_string.t, string) result]
      expected
      got
  in
  "encrypt_with_ad_low" >:::
  [ "RFC 7539 2.8.2" >:: test
      ~plaintext:
        ( Cstruct.of_string
            ( String.concat ""
                [ "Ladies and Gentlemen of the class of '99: "
                ; "If I could offer you only one tip for the "
                ; "future, sunscreen would be it."
                ]
            )
        )
      ~ad:(of_hex "50515253c0c1c2c3c4c5c6c7")
      ~key:(
        Noise.Private_key.of_bytes
          ( of_hexdump
              [ "808182838485868788898a8b8c8d8e8f"
              ; "909192939495969798999a9b9c9d9e9f"
              ]
          )
      )
      ~iv:(of_hex "4041424344454647")
      ~fixed:(of_hex "07000000")
      ~expected_ciphertext:(
        of_hexdump
          [ "d31a8d34648e60db7b86afbc53ef7ec2"
          ; "a4aded51296e08fea9e2b5a736ee62d6"
          ; "3dbea45e8ca9671282fafb69da92728b"
          ; "1a71de0a9e060b2905d6a5b67ecd3b36"
          ; "92ddbd7f2d778b8c9803aee328091b58"
          ; "fab324e4fad675945585808b4831d7bc"
          ; "3ff4def08e4b7a9de576d26586cec64b"
          ; "6116"
          ]
      )
      ~expected_tag:(
        of_hex "1ae10b594f09e26a7e902ecbd0600691"
      )
  ]

let suite =
  "Cipher_chacha_poly" >:::
  [ test_encrypt
  ]

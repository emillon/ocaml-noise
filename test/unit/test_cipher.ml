open OUnit2
open Test_helpers.Infix

let test_of_string =
  let should_be expected s ctxt =
    let got = Noise.Cipher.of_string s in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Noise.Cipher.t, string) result]
      ~printer:[%show: (Noise.Cipher.t, string) result]
      expected
      got
  in
  "of_string" >:::
  [ "AESGCM" >:= should_be (Ok AES_GCM)
  ; "ChaChaPoly" >:= should_be (Ok Chacha_poly)
  ]

let suite =
  "Cipher" >:::
  [ test_of_string
  ]

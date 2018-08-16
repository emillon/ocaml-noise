open OUnit2

let test_hash =
  let test hex expected_lines ctxt =
    let cs = Hex.to_cstruct hex in
    let got = Noise.Hash_blake2s.hash cs in
    let expected_hex = `Hex (String.concat "" expected_lines) in
    let expected = Hex.to_cstruct expected_hex in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t]
      expected
      got
  in
  "hash" >:::
  [ "RFC7693 Annex B" >:: test
      (`Hex "616263")
      [ "508C5E8C327C14E2E1A72BA34EEB452F"
      ; "37458B209ED63A294D999B4C86675982"
      ]
  ; "Test vector, len=0" >:: test
      (`Hex "")
      [ "69217a3079908094e11121d042354a7c"
      ; "1f55b6482ca1a51e1b250dfd1ed0eef9"
      ]
  ; "Test vector, len=1" >:: test
      (`Hex "00")
      [ "e34d74dbaf4ff4c6abd871cc220451d2"
      ; "ea2648846c7757fbaac82fe51ad64bea"
      ]
  ; "Test vector, len=2" >:: test
      (`Hex "0001")
      [ "ddad9ab15dac4549ba42f49d262496be"
      ; "f6c0bae1dd342a8808f8ea267c6e210c"
      ]
  ]

let test_hmac =
  let test ~input ~key ~expected ctxt =
    let input = Hex.to_cstruct input in
    let key = Hex.to_cstruct key in
    let expected = Hex.to_cstruct expected in
    let got = Noise.Hash_blake2s.hmac input ~key in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t]
      expected
      got
  in
  "hmac" >:::
  [ "It is not the keyed hash" >:: test
    ~input:(`Hex "0001")
    ~key:(`Hex "1234")
    ~expected:(`Hex "02cb35c062930b48a20d7eb4b8e3014e148cd7a777c26efe2ee8caa585e8a169")
  ]

let suite =
  "BLAKE2s" >:::
  [ test_hash
  ; test_hmac
  ]

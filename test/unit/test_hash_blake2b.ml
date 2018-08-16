open OUnit2

let test_hmac =
  let test ~input ~key ~expected ctxt =
    let input = Hex.to_cstruct input in
    let key = Hex.to_cstruct key in
    let expected = Hex.to_cstruct expected in
    let got = Noise.Hash_blake2b.hmac input ~key in
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
    ~expected:(`Hex "58997747708654916fc742a81558bd651e7069905c38ac395cf9ec56d43dd2eb059912236ff4e78a64fec21ca68cf4e170a3c1e749e72a194627cd935131f281")
  ]

let suite =
  "BLAKE2b" >:::
  [ test_hmac
  ]

open OUnit2
open Test_helpers.Infix

let test_of_string =
  let should_be expected s ctxt =
    let got = Noise.Hash.of_string s in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Noise.Hash.t, string) result]
      ~printer:[%show: (Noise.Hash.t, string) result]
      expected
      got
  in
  "of_string" >:::
  [ "SHA256" >:= should_be (Ok SHA256)
  ; "SHA512" >:= should_be (Ok SHA512)
  ]

let test_len =
  let test h expected ctxt =
    let got = Noise.Hash.len h in
    assert_equal
      ~ctxt
      ~cmp:[%eq: int]
      ~printer:[%show: int]
      expected
      got
  in
  "len" >:::
  [ "SHA256" >:: test SHA256 32
  ; "SHA512" >:: test SHA512 64
  ]

let suite =
  "Hash" >:::
  [ test_of_string
  ; test_len
  ]

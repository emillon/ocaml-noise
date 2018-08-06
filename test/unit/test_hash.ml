open OUnit2
open Helpers.Infix

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
  [ "BLAKE2s" >:= should_be (Ok BLAKE2s)
  ; "BLAKE2b" >:= should_be (Ok BLAKE2b)
  ; "SHA256" >:= should_be (Ok SHA256)
  ; "SHA512" >:= should_be (Ok SHA512)
  ]

let suite =
  "Hash" >:::
  [ test_of_string
  ]

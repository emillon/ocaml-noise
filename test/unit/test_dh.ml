open OUnit2
open Helpers.Infix

let test_of_string =
  let should_be expected s ctxt =
    let got = Noise.Dh.of_string s in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Noise.Dh.t, string) result]
      ~printer:[%show: (Noise.Dh.t, string) result]
      expected
      got
  in
  "of_string" >:::
  [ "25519" >:= should_be (Ok Curve_25519)
  ; "448" >:= should_be (Ok Curve_448)
  ]

let suite =
  "Dh" >:::
  [ test_of_string
  ]

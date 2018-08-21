open OUnit2
open Test_helpers.Infix

let test_of_string =
  let should_be expected s ctxt =
    let got = Noise.Pattern.of_string s in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Noise.Pattern.t, string) result]
      ~printer:[%show: (Noise.Pattern.t, string) result]
      expected
      got
  in
  "of_string" >:::
  [ "N" >:= should_be (Ok N)
  ; "K" >:= should_be (Ok K)
  ; "X" >:= should_be (Ok X)
  ; "NN" >:= should_be (Ok NN)
  ; "NX" >:= should_be (Ok NX)
  ]

let suite =
  "Pattern" >:::
  [ test_of_string
  ]

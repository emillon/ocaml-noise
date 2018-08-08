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
  ]

let suite =
  "Pattern" >:::
  [ test_of_string
  ]

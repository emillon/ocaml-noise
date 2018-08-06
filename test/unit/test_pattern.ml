open OUnit2

let (>:=) s f =
  s >:: f s

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
  ; "X" >:= should_be (Ok X)
  ; "K" >:= should_be (Ok K)
  ; "NN" >:= should_be (Ok NN)
  ; "NK" >:= should_be (Ok NK)
  ; "NX" >:= should_be (Ok NX)
  ; "XN" >:= should_be (Ok XN)
  ; "XK" >:= should_be (Ok XK)
  ; "XX" >:= should_be (Ok XX)
  ; "KN" >:= should_be (Ok KN)
  ; "KK" >:= should_be (Ok KK)
  ; "KX" >:= should_be (Ok KX)
  ; "IN" >:= should_be (Ok IN)
  ; "IK" >:= should_be (Ok IK)
  ; "IX" >:= should_be (Ok IX)
  ]

let suite =
  "Pattern" >:::
  [ test_of_string
  ]

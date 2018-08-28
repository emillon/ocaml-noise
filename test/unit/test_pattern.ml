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
  ; "IN" >:= should_be (Ok IN)
  ; "XN" >:= should_be (Ok XN)
  ; "XX" >:= should_be (Ok XX)
  ; "IX" >:= should_be (Ok IX)
  ; "NK" >:= should_be (Ok NK)
  ; "IK" >:= should_be (Ok IK)
  ; "KN" >:= should_be (Ok KN)
  ; "KK" >:= should_be (Ok KK)
  ; "KX" >:= should_be (Ok KX)
  ; "XK" >:= should_be (Ok XK)
  ; "IKpsk1" >:= should_be (Ok IKpsk1)
  ; "IKpsk2" >:= should_be (Ok IKpsk2)
  ; "INpsk1" >:= should_be (Ok INpsk1)
  ; "INpsk2" >:= should_be (Ok INpsk2)
  ; "IXpsk2" >:= should_be (Ok IXpsk2)
  ; "KKpsk0" >:= should_be (Ok KKpsk0)
  ; "KKpsk2" >:= should_be (Ok KKpsk2)
  ; "KNpsk0" >:= should_be (Ok KNpsk0)
  ; "KNpsk2" >:= should_be (Ok KNpsk2)
  ; "KXpsk2" >:= should_be (Ok KXpsk2)
  ; "NKpsk0" >:= should_be (Ok NKpsk0)
  ; "NKpsk2" >:= should_be (Ok NKpsk2)
  ; "NNpsk0" >:= should_be (Ok NNpsk0)
  ; "NNpsk2" >:= should_be (Ok NNpsk2)
  ; "NXpsk2" >:= should_be (Ok NXpsk2)
  ; "XKpsk3" >:= should_be (Ok XKpsk3)
  ; "XNpsk3" >:= should_be (Ok XNpsk3)
  ; "XXpsk3" >:= should_be (Ok XXpsk3)
  ; "Npsk0" >:= should_be (Ok Npsk0)
  ; "Xpsk1" >:= should_be (Ok Xpsk1)
  ; "Kpsk0" >:= should_be (Ok Kpsk0)
  ]

let suite =
  "Pattern" >:::
  [ test_of_string
  ]

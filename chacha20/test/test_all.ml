open OUnit2

let test_quarter_round =
  let test x expected ctxt =
    let got = Chacha20.quarter_round x in
    assert_equal
      ~ctxt
      ~cmp:[%eq: int32 * int32 * int32 * int32]
      ~printer:[%show: int32 * int32 * int32 * int32]
      expected
      got
  in
  "quarter_round" >:::
  [ "RFC 7539 2.1.1" >:: test
   ( 0x11111111l
   , 0x01020304l
   , 0x9b8d6f43l
   , 0x01234567l
   )
   ( 0xea2a92f4l
   , 0xcb1cf8cel
   , 0x4581472el
   , 0x5881c4bbl
   )
  ]

let suite =
  "Chacha20" >:::
  [ test_quarter_round
  ]

let () = run_test_tt_main suite

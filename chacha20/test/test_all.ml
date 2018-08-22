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

let test_quarter_round_state =
  let test s i expected ctxt =
    let got = Chacha20.quarter_round_state s i in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Chacha20.state]
      ~printer:[%show: Chacha20.state]
      expected
      got
  in
  "quarter_round_state" >:::
  [ "RFC 7539 2.2.1" >:: test
      ( Chacha20.make_state
          [ 0x879531e0l; 0xc5ecf37dl; 0x516461b1l; 0xc9a62f8al
          ; 0x44c20ef3l; 0x3390af7fl; 0xd9fc690bl; 0x2a5f714cl
          ; 0x53372767l; 0xb00a5631l; 0x974c541al; 0x359e9963l
          ; 0x5c971061l; 0x3d631689l; 0x2098d9d6l; 0x91dbd320l
          ]
      )
      (2, 7, 8, 13)
      ( Chacha20.make_state
          [ 0x879531e0l; 0xc5ecf37dl; 0xbdb886dcl; 0xc9a62f8al
          ; 0x44c20ef3l; 0x3390af7fl; 0xd9fc690bl; 0xcfacafd2l
          ; 0xe46bea80l; 0xb00a5631l; 0x974c541al; 0x359e9963l
          ; 0x5c971061l; 0xccc07c79l; 0x2098d9d6l; 0x91dbd320l
          ]
      )
  ]

let suite =
  "Chacha20" >:::
  [ test_quarter_round
  ; test_quarter_round_state
  ]

let () = run_test_tt_main suite

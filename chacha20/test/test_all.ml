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

let test_make_state_for_encryption =
  let test ~key ~nonce ~count expected ctxt =
    let got = Chacha20.make_state_for_encryption ~key ~nonce ~count in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Chacha20.state, string) result]
      ~printer:[%show: (Chacha20.state, string) result]
      expected
      got
  in
  (* data from RFC 7539 2.3.2 *)
  let key =
    Hex.to_cstruct
      ( `Hex
          ( "000102030405060708090a0b0c0d0e0f"
          ^ "101112131415161718191a1b1c1d1e1f"
          )
      )
  in
  let nonce =
    Hex.to_cstruct
      (`Hex "000000090000004a00000000")
  in
  let count = 1l in
  "make_state_for_encryption" >:::
  [ "key with wrong length" >:: test
      ~key:(Cstruct.create 3)
      ~nonce
      ~count
      (Error "wrong key length")
  ; "Nonce with wrong length" >:: test
      ~key
      ~nonce:(Cstruct.create 3)
      ~count
      (Error "wrong nonce length")
  ; "OK" >:: test
      ~key
      ~nonce
      ~count
      ( Ok
          ( Chacha20.make_state
              [ 0x61707865l; 0x3320646el; 0x79622d32l; 0x6b206574l
              ; 0x03020100l; 0x07060504l; 0x0b0a0908l; 0x0f0e0d0cl
              ; 0x13121110l; 0x17161514l; 0x1b1a1918l; 0x1f1e1d1cl
              ; 0x00000001l; 0x09000000l; 0x4a000000l; 0x00000000l
              ]
          )
      )
  ]

let suite =
  "Chacha20" >:::
  [ test_quarter_round
  ; test_quarter_round_state
  ; test_make_state_for_encryption
  ]

let () = run_test_tt_main suite

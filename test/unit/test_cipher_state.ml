open OUnit2

let test_incr_nonce =
  let test cipher_state expected ctxt =
    let got = Noise.Cipher_state.incr_nonce cipher_state in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Noise.Cipher_state.t]
      ~printer:[%show: Noise.Cipher_state.t]
      expected
      got
  in
  let make nonce =
    let key = Noise.Private_key.of_bytes @@ Cstruct.of_hex "12" in
    Noise.Cipher_state.Ready {key; nonce}
  in
  "incr_nonce" >:::
  [ "Normal" >:: test
      (make 3L)
      (make 4L)
  ; "Uninitialized" >:: test
      Noise.Cipher_state.Empty
      Noise.Cipher_state.Empty
  ; "Overflow" >:: test
      (make 0x7f_ff_ff_ff_ff_ff_ff_ffL)
      (make 0x80_00_00_00_00_00_00_00L)
  ; "End" >:: test
      (make 0xff_ff_ff_ff_ff_ff_ff_feL)
      Noise.Cipher_state.Depleted
  ; "Depleted" >:: test
      Noise.Cipher_state.Depleted
      Noise.Cipher_state.Depleted
  ]

let suite =
  "Cipher_state" >:::
  [ test_incr_nonce
  ]

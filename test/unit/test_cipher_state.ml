open OUnit2

module Data = struct
  let key = Noise.Private_key.of_bytes @@ Cstruct.of_hex "12"

  let make nonce =
    Noise.Cipher_state.create
      ~unsafe_nonce:nonce
      key

  let other_key = Noise.Private_key.of_bytes @@ Cstruct.of_hex "34"
end

let test_with_ =
  let test cipher_state expected ctxt =
    let got =
      Noise.Cipher_state.with_
        cipher_state
        (fun ~key:_ ~nonce:_ b -> Ok (not b))
        true
    in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (Noise.Cipher_state.t * bool, string) result]
      ~printer:[%show: (Noise.Cipher_state.t * bool, string) result]
      expected
      got
  in
  let open Data in
  let test_ready cipher_state ~expected_nonce_used ~expected_state =
     fun ctxt ->
      let other_nonce = 1L in
      let got =
        Noise.Cipher_state.with_
          cipher_state
          (fun ~key ~nonce (_, _, b) -> Ok (key, nonce, not b))
          (other_key, other_nonce, true)
      in
      let expected = Ok (expected_state, (key, expected_nonce_used, false)) in
      assert_equal
        ~ctxt
        ~cmp:[%eq: (Noise.Cipher_state.t * (Noise.Private_key.t * int64 * bool), string) result]
        ~printer:[%show: (Noise.Cipher_state.t * (Noise.Private_key.t * int64 * bool), string) result]
        expected
        got
  in
  "with_" >:::
  [ "When empty, it does not apply the function" >:: test
      Noise.Cipher_state.empty
      (Ok (Noise.Cipher_state.empty, true))
  ; "When depleted, it returns an error" >:: test
      Noise.Cipher_state.depleted
      (Error "Nonce depleted")
  ; "When ready, it passes the state and increments the nonce" >:::
    [ "Normal" >:: test_ready
        (make 3L)
        ~expected_nonce_used:3L
        ~expected_state:(make 4L)
    ; "Overflow" >:: test_ready
        (make 0x7f_ff_ff_ff_ff_ff_ff_ffL)
        ~expected_nonce_used:0x7f_ff_ff_ff_ff_ff_ff_ffL
        ~expected_state:(make 0x80_00_00_00_00_00_00_00L)
    ; "End" >:: test_ready
        (make 0xff_ff_ff_ff_ff_ff_ff_feL)
        ~expected_nonce_used:0xff_ff_ff_ff_ff_ff_ff_feL
        ~expected_state:Noise.Cipher_state.depleted
    ]
  ]

let test_has_key =
  let test cipher_state expected ctxt =
    let got = Noise.Cipher_state.has_key cipher_state in
    assert_equal
      ~ctxt
      ~cmp:[%eq: bool]
      ~printer:[%show: bool]
      expected
      got
  in
  "has_key" >:::
  [ "Empty" >:: test Noise.Cipher_state.empty false
  ; "Ready" >:: test (Data.make 0L) true
  ; "Depleted: we still expect to be able to decrypt" >:: test
      Noise.Cipher_state.depleted true
  ]

let suite =
  "Cipher_state" >:::
  [ test_with_
  ; test_has_key
  ]

open OUnit2

module Data = struct
  let of_hex s =
    Hex.to_cstruct (`Hex s)

  let pub_of_hex s =
    Noise.Public_key.of_bytes (of_hex s)

  let priv_of_hex s =
    Noise.Private_key.of_bytes (of_hex s)

  (* From https://cr.yp.to/highspeed/naclcrypto-20090310.pdf *)
  let alicesk = priv_of_hex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let bobpk = pub_of_hex "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  let bobsk = priv_of_hex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  let alicepk = pub_of_hex "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  let shared = of_hex "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  let bytes31 = Cstruct.create 31
end

let test_key_exchange =
  let test priv pub expected ctxt =
    let got = Noise.Dh_25519.key_exchange ~priv ~pub in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Test_helpers.Hex_string.t]
      ~printer:[%show: Test_helpers.Hex_string.t]
      expected
      got
  in
  let test_exn priv pub _ctxt =
    assert_raises Tweetnacl.Wrong_key_size @@ fun () ->
    Noise.Dh_25519.key_exchange ~priv ~pub
  in
  let open Data in
  "key_exchange" >:::
  [ "Priv A, Pub B" >:: test alicesk bobpk shared
  ; "Priv B, Pub A" >:: test bobsk alicepk shared
  ; "Wrong size in priv" >:: test_exn (Noise.Private_key.of_bytes bytes31) alicepk
  ; "Wrong size in pub" >:: test_exn alicesk (Noise.Public_key.of_bytes bytes31) 
  ]

let test_corresponds =
  let test priv pub expected ctxt =
    let got = Noise.Dh_25519.corresponds ~priv ~pub in
    assert_equal
      ~ctxt
      ~cmp:[%eq: bool]
      ~printer:[%show: bool]
      expected
      got
  in
  let open Data in
  "corresponds" >:::
  [ "Priv A, Pub A" >:: test alicesk alicepk true
  ; "Priv A, Pub B" >:: test alicesk bobpk false
  ; "Priv B, Pub A" >:: test bobsk alicepk false
  ; "Priv B, Pub B" >:: test bobsk bobpk true
  ]


let suite =
  "Dh_25519" >:::
  [ test_key_exchange
  ; test_corresponds
  ]

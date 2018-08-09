open OUnit2

let suite =
  "Unit tests" >:::
  [ Test_cipher.suite
  ; Test_cipher_aes_gcm.suite
  ; Test_dh.suite
  ; Test_dh_25519.suite
  ; Test_hash.suite
  ; Test_hkdf.suite
  ; Test_pattern.suite
  ]

let () =
  run_test_tt_main suite

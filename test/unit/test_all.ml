open OUnit2

let suite =
  "Unit tests" >:::
  [ Test_pattern.suite
  ]

let () =
  run_test_tt_main suite

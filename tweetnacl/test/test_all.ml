open OUnit2

let equal_cstruct = Cstruct.equal
let pp_cstruct = Cstruct.hexdump_pp

let test_poly1305 =
  let test ~key ~msg expected ctxt =
    let got =
      match Tweetnacl.poly1305 ~key msg with
      | x -> Some x
      | exception Tweetnacl.Wrong_key_size -> None
    in
    assert_equal
      ~ctxt
      ~cmp:[%eq: cstruct option]
      ~printer:[%show: cstruct option]
      expected
      got
  in
  let msg = Cstruct.of_string "Cryptographic Forum Research Group" in
  "poly1305" >:::
  [ "RFC 7539 2.5.2" >:: test
      ~key:
        ( Hex.to_cstruct
            ( `Hex
                (String.concat ""
                   [ "85d6be7857556d337f4452fe42d506a8"
                   ; "0103808afb0db2fd4abff6af4149f51b"
                   ]
                )
            )
        )
      ~msg
      (Some (Hex.to_cstruct (`Hex "a8061dc1305136c6c22b8baf0c0127a9")))
  ; "Key with wrong size" >:: test
      ~key:(Cstruct.create 3)
      ~msg
      None
  ]

let suite =
  "Tweetnacl" >:::
  [ test_poly1305
  ]


let () = run_test_tt_main suite

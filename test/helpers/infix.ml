open OUnit2

let (>:=) s f =
  s >:: f s

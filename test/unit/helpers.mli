module Infix : sig
  val (>:=) : string -> (string -> OUnit2.test_fun) -> OUnit2.test
end

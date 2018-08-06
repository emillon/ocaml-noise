open OUnit2

module Infix = struct
  let (>:=) s f =
    s >:: f s
end

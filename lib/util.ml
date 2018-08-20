let (>>=) x f =
  match x with
  | Ok x -> f x
  | Error _ as e -> e

let (>>|) x f =
  x >>= fun y -> Ok (f y)

let (>>|) x f =
  match x with
  | Ok x -> Ok (f x)
  | Error _ as e -> e

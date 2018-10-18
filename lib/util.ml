let equal_constant_time a b =
  Eqaf.equal (Cstruct.to_string a) (Cstruct.to_string b)

module Let_syntax = struct
  let bind x ~f =
    match x with
    | Ok x ->
        f x
    | Error _ as e ->
        e

  let map x ~f = bind x ~f:(fun y -> Ok (f y))
end

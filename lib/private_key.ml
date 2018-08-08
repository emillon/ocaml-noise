type t = Private of Cstruct.t

let bytes (Private cs) = cs

let of_bytes cs = Private cs

type t = Public of Cstruct.t

let bytes (Public cs) = cs

let of_bytes cs = Public cs

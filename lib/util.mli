val ( >>= ) : ('a, 'e) result -> ('a -> ('b, 'e) result) -> ('b, 'e) result

val ( >>| ) : ('a, 'e) result -> ('a -> 'b) -> ('b, 'e) result

val equal_constant_time : Cstruct.t -> Cstruct.t -> bool

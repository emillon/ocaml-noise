val equal_constant_time : Cstruct.t -> Cstruct.t -> bool

module Let_syntax : sig
  val map : ('a, 'e) result -> f:('a -> 'b) -> ('b, 'e) result

  val bind : ('a, 'e) result -> f:('a -> ('b, 'e) result) -> ('b, 'e) result
end

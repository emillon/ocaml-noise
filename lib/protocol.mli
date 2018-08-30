val initialize :
  State.t -> prologue:Cstruct.t -> public_keys:Public_key.t list -> State.t
(** Hash the public data *)

val read_message :
  State.t -> Cstruct.t -> (State.t * Cstruct.t, string) result

val write_message :
  State.t -> Cstruct.t -> (State.t * Cstruct.t, string) result

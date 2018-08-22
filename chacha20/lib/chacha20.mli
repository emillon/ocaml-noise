val quarter_round :
  int32 * int32 * int32 * int32 ->
  int32 * int32 * int32 * int32

type state
[@@deriving eq,show]

val make_state :
  int32 list ->
  state

val quarter_round_state :
  state ->
  int * int * int * int ->
  state

val make_state_for_encryption :
  key:Cstruct.t ->
  nonce:Cstruct.t ->
  count:int32 ->
  (state, string) result

val process : state -> state

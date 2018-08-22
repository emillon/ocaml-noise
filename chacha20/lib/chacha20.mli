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

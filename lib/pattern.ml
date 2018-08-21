type t =
  | N
  | K
  | X
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | "X" -> Ok X
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

type step =
  | E
  | ES
  | S
  | SS

let all_steps = function
  | N -> [[E; ES]]
  | K -> [[E; ES; SS]]
  | X -> [[E; ES; S; SS]]

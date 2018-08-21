type t =
  | N
  | K
  | X
  | NN
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | "X" -> Ok X
  | "NN" -> Ok NN
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

type step =
  | E
  | ES
  | S
  | SS
  | EE

let all_steps = function
  | N -> [[E; ES]]
  | K -> [[E; ES; SS]]
  | X -> [[E; ES; S; SS]]
  | NN -> [[E]; [E; EE]]

type transport =
  | One_way
  | Two_way

let transport = function
  | N
  | K
  | X
    ->
    One_way
  | NN
    ->
    Two_way

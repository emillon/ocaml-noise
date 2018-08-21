type t =
  | N
  | K
  | X
  | NN
  | NX
  | IN
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | "X" -> Ok X
  | "NN" -> Ok NN
  | "NX" -> Ok NX
  | "IN" -> Ok IN
  | s -> Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

type step =
  | E
  | ES
  | S
  | SS
  | EE
  | SE

let all_steps = function
  | N -> [[E; ES]]
  | K -> [[E; ES; SS]]
  | X -> [[E; ES; S; SS]]
  | NN -> [[E]; [E; EE]]
  | NX -> [[E]; [E; EE; S; ES]]
  | IN -> [[E; S]; [E; EE; SE]]

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
  | NX
  | IN
    ->
    Two_way

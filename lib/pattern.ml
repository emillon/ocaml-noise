type t =
  | N
  | K
  | X
  | NN
  | NX
  | IN
  | XN
  | XX
[@@deriving eq,show]

let of_string = function
  | "N" -> Ok N
  | "K" -> Ok K
  | "X" -> Ok X
  | "NN" -> Ok NN
  | "NX" -> Ok NX
  | "IN" -> Ok IN
  | "XN" -> Ok XN
  | "XX" -> Ok XX
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
  | XN -> [[E]; [E; EE]; [S; SE]]
  | XX -> [[E]; [E; EE; S; ES]; [S; SE]]

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
  | XN
  | XX
    ->
    Two_way

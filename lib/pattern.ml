type t =
  | N
  | K
  | X
  | NN
  | NX
  | IN
  | XN
  | XX
  | IX
  | NK
  | IK
  | KN
  | KK
  | KX
  | XK
  | IKpsk1
  | IKpsk2
  | INpsk1
  | INpsk2
  | IXpsk2
  | KKpsk0
  | KKpsk2
  | KNpsk0
  | KNpsk2
  | KXpsk2
  | NKpsk0
  | NKpsk2
  | NNpsk0
  | NNpsk2
  | NXpsk2
  | XKpsk3
  | XNpsk3
  | XXpsk3
  | Npsk0
  | Xpsk1
  | Kpsk0
[@@deriving eq, show]

let of_string = function
  | "N" ->
      Ok N
  | "K" ->
      Ok K
  | "X" ->
      Ok X
  | "NN" ->
      Ok NN
  | "NX" ->
      Ok NX
  | "IN" ->
      Ok IN
  | "XN" ->
      Ok XN
  | "XX" ->
      Ok XX
  | "IX" ->
      Ok IX
  | "NK" ->
      Ok NK
  | "IK" ->
      Ok IK
  | "KN" ->
      Ok KN
  | "KK" ->
      Ok KK
  | "KX" ->
      Ok KX
  | "XK" ->
      Ok XK
  | "IKpsk1" ->
      Ok IKpsk1
  | "IKpsk2" ->
      Ok IKpsk2
  | "NNpsk0" ->
      Ok NNpsk0
  | "NNpsk2" ->
      Ok NNpsk2
  | "NKpsk0" ->
      Ok NKpsk0
  | "NKpsk2" ->
      Ok NKpsk2
  | "NXpsk2" ->
      Ok NXpsk2
  | "KNpsk0" ->
      Ok KNpsk0
  | "KNpsk2" ->
      Ok KNpsk2
  | "KKpsk0" ->
      Ok KKpsk0
  | "KKpsk2" ->
      Ok KKpsk2
  | "KXpsk2" ->
      Ok KXpsk2
  | "INpsk1" ->
      Ok INpsk1
  | "INpsk2" ->
      Ok INpsk2
  | "IXpsk2" ->
      Ok IXpsk2
  | "XNpsk3" ->
      Ok XNpsk3
  | "XKpsk3" ->
      Ok XKpsk3
  | "XXpsk3" ->
      Ok XXpsk3
  | "Npsk0" ->
      Ok Npsk0
  | "Kpsk0" ->
      Ok Kpsk0
  | "Xpsk1" ->
      Ok Xpsk1
  | s ->
      Printf.ksprintf (fun e -> Error e) "Pattern.of_string: %s" s

type step =
  | E
  | ES
  | S
  | SS
  | EE
  | SE
  | PSK

let all_steps = function
  | N ->
      [[E; ES]]
  | K ->
      [[E; ES; SS]]
  | X ->
      [[E; ES; S; SS]]
  | NN ->
      [[E]; [E; EE]]
  | NX ->
      [[E]; [E; EE; S; ES]]
  | IN ->
      [[E; S]; [E; EE; SE]]
  | XN ->
      [[E]; [E; EE]; [S; SE]]
  | XX ->
      [[E]; [E; EE; S; ES]; [S; SE]]
  | IX ->
      [[E; S]; [E; EE; SE; S; ES]]
  | NK ->
      [[E; ES]; [E; EE]]
  | IK ->
      [[E; ES; S; SS]; [E; EE; SE]]
  | KN ->
      [[E]; [E; EE; SE]]
  | KK ->
      [[E; ES; SS]; [E; EE; SE]]
  | KX ->
      [[E]; [E; EE; SE; S; ES]]
  | XK ->
      [[E; ES]; [E; EE]; [S; SE]]
  | IKpsk1 ->
      [[E; ES; S; SS; PSK]; [E; EE; SE]]
  | IKpsk2 ->
      [[E; ES; S; SS]; [E; EE; SE; PSK]]
  | NNpsk0 ->
      [[PSK; E]; [E; EE]]
  | NNpsk2 ->
      [[E]; [E; EE; PSK]]
  | NKpsk0 ->
      [[PSK; E; ES]; [E; EE]]
  | NKpsk2 ->
      [[E; ES]; [E; EE; PSK]]
  | NXpsk2 ->
      [[E]; [E; EE; S; ES; PSK]]
  | KNpsk0 ->
      [[PSK; E]; [E; EE; SE]]
  | KNpsk2 ->
      [[E]; [E; EE; SE; PSK]]
  | KKpsk0 ->
      [[PSK; E; ES; SS]; [E; EE; SE]]
  | KKpsk2 ->
      [[E; ES; SS]; [E; EE; SE; PSK]]
  | KXpsk2 ->
      [[E]; [E; EE; SE; S; ES; PSK]]
  | INpsk1 ->
      [[E; S; PSK]; [E; EE; SE]]
  | INpsk2 ->
      [[E; S]; [E; EE; SE; PSK]]
  | IXpsk2 ->
      [[E; S]; [E; EE; SE; S; ES; PSK]]
  | XNpsk3 ->
      [[E]; [E; EE]; [S; SE; PSK]]
  | XKpsk3 ->
      [[E; ES]; [E; EE]; [S; SE; PSK]]
  | XXpsk3 ->
      [[E]; [E; EE; S; ES]; [S; SE; PSK]]
  | Npsk0 ->
      [[PSK; E; ES]]
  | Kpsk0 ->
      [[PSK; E; ES; SS]]
  | Xpsk1 ->
      [[E; ES; S; SS; PSK]]

type transport =
  | One_way
  | Two_way

let transport = function
  | N
  | K
  | X
  | Npsk0
  | Xpsk1
  | Kpsk0 ->
      One_way
  | NN
  | NX
  | IN
  | XN
  | XX
  | IX
  | NK
  | IK
  | KN
  | KK
  | KX
  | XK
  | IKpsk1
  | IKpsk2
  | NNpsk0
  | NNpsk2
  | NKpsk0
  | NKpsk2
  | NXpsk2
  | KNpsk0
  | KNpsk2
  | KKpsk0
  | KKpsk2
  | KXpsk2
  | INpsk1
  | INpsk2
  | IXpsk2
  | XNpsk3
  | XKpsk3
  | XXpsk3 ->
      Two_way

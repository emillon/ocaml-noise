val (>>=) :
  ('a, 'e) result ->
  ('a -> ('b, 'e) result) ->
  ('b, 'e) result

val (>>|) :
  ('a, 'e) result ->
  ('a -> 'b) ->
  ('b, 'e) result

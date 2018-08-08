let extract ~hmac ~salt ~ikm =
  hmac ~key:salt ikm

let b01 =
  Cstruct.of_hex "01"

let b02 =
  Cstruct.of_hex "02"

let hkdf2 ~hmac ~salt ~ikm =
  let temp_key = extract ~hmac ~salt ~ikm in
  let output1 = hmac ~key:temp_key b01 in
  let output2 = hmac ~key:temp_key (Cstruct.concat [output1; b02]) in
  (output1, output2)

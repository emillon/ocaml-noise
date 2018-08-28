let extract ~hmac ~salt ~ikm =
  hmac ~key:salt ikm

let b01 =
  Cstruct.of_hex "01"

let b02 =
  Cstruct.of_hex "02"

let b03 =
  Cstruct.of_hex "03"

let hkdf2_k ~hmac ~temp_key =
  let output1 = hmac ~key:temp_key b01 in
  let output2 = hmac ~key:temp_key (Cstruct.concat [output1; b02]) in
  (output1, output2)

let hkdf2 ~hmac ~salt ~ikm =
  let temp_key = extract ~hmac ~salt ~ikm in
  hkdf2_k ~hmac ~temp_key

let hkdf3_k ~hmac ~temp_key =
  let (output1, output2) = hkdf2_k ~hmac ~temp_key in
  let output3 = hmac ~key:temp_key (Cstruct.concat [output2; b03]) in
  (output1, output2, output3)

let hkdf3 ~hmac ~salt ~ikm =
  let temp_key = extract ~hmac ~salt ~ikm in
  hkdf3_k ~hmac ~temp_key

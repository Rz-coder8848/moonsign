///|
fn hex_of(bytes : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    let value = bytes[i].to_int()
    buf.write_char(digits.get_char(value / 16).unwrap())
    buf.write_char(digits.get_char(value % 16).unwrap())
  }
  buf.to_string()
}

///|
fn bytes_of(hex : String) -> Bytes {
  let length = hex.length() / 2
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    let high = hex_value(hex.get_char(i * 2).unwrap())
    let low = hex_value(hex.get_char(i * 2 + 1).unwrap())
    out[i] = (high * 16 + low).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
fn hex_value(c : Char) -> Int32 {
  let code = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else {
    code - 55
  }
}

///|
test "pkcs12 kdf vector" {
  let password = bmp_password("test")
  inspect(hex_of(password), content="00740065007300740000")
  let salt = bytes_of("4c635d88a9c22cd0")
  let key = pkcs12_kdf(@crypto.Hash::Sha256, password, salt, 3, 2048, 32)
  inspect(
    hex_of(key),
    content="6a8d311f58435a0527b1ae1461fa5b7431f9985ffeb50af664716a43864f05e7",
  )
}

///|
test "pbkdf2 vector" {
  let salt = bytes_of("60ed61f348df394a0155865d5318f906")
  let key = @crypto.pbkdf2_sha256(@utf8.encode("test"), salt, 2048, 32)
  inspect(
    hex_of(key),
    content="8efa05aa61db2932c6f2b7aa36bd337670157a563ceb5c6110a2f09655d99a99",
  )
}

///|
test "aes cbc vector" {
  let key = Array::make(32, b'\x00')
  for i in 0..<32 {
    key[i] = i.to_byte()
  }
  let iv = Bytes::from_array(Array::make(16, b'\x00')[:])
  let ct = bytes_of("b5d0a523a6cb5cc065856200628c2a42")
  let plain = match
    @crypto.aes_cbc_decrypt_checked(ct, Bytes::from_array(key[:]), iv) {
    Ok(value) => value
    Err(_) => abort("decrypt")
  }
  inspect(hex_of(plain), content="303132333435363738396162636465")
}

///|
/// PBKDF2 with HMAC-SHA1 (used by PBES2 / PKCS#12).
pub fn pbkdf2_sha1(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  length : Int32,
) -> Bytes {
  @mooncry.pbkdf2_hmac_sha1(password, salt, iterations, length)
}

///|
/// PBKDF2 with HMAC-SHA256.
pub fn pbkdf2_sha256(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  length : Int32,
) -> Bytes {
  @mooncry.pbkdf2_hmac_sha256(password, salt, iterations, length)
}

///|
/// HMAC-SHA1.
pub fn hmac_sha1(key : Bytes, message : Bytes) -> Bytes {
  @mooncry.hmac_sha1(key, message)
}

///|
/// HMAC-SHA256.
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  @mooncry.hmac_sha256(key, message)
}

///|
/// AES-CBC decryption without padding removal.
pub fn aes_cbc_decrypt(data : Bytes, key : Bytes, iv : Bytes) -> Bytes {
  @mooncry.aes_decrypt_cbc(data, key, iv)
}

///|
fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(a.length() + b.length(), b'\x00')
  for i in 0..<a.length() {
    out[i] = a[i]
  }
  for i in 0..<b.length() {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out[:])
}

///|
/// AES-CBC decryption with strict PKCS#7 padding.
///
/// `data` is the ciphertext only; the IV is prepended for the underlying
/// implementation, which expects an IV-prefixed blob.
pub fn aes_cbc_decrypt_checked(
  data : Bytes,
  key : Bytes,
  iv : Bytes,
) -> Result[Bytes, String] {
  @mooncry.aes_decrypt_cbc_or(concat_bytes(iv, data), key, iv)
}

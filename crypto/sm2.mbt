///|
fn sm2_concat(a : Bytes, b : Bytes) -> Bytes {
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
fn sm2_counter_bytes(value : Int32) -> Bytes {
  let out = Array::make(4, b'\x00')
  out[0] = ((value >> 24) & 0xFF).to_byte()
  out[1] = ((value >> 16) & 0xFF).to_byte()
  out[2] = ((value >> 8) & 0xFF).to_byte()
  out[3] = (value & 0xFF).to_byte()
  Bytes::from_array(out[:])
}

///|
/// Sign `message` with SM2 and the default signer ID, returning a DER
/// `SEQUENCE { r, s }` signature.
///
/// The nonce is derived deterministically from the key and message with
/// HMAC-SM3 (RFC 6979 style), so signatures are reproducible and nonce reuse
/// only happens for identical messages.
pub fn sign_sm2(sk : Bytes, message : Bytes) -> Bytes {
  let id = @utf8.encode("1234567812345678")
  let counter = Ref(0)
  let signature = @mooncry.sm2_sign(sk, message, id, fn(_length) {
    let current = counter.val
    let k = @mooncry.hmac_sm3(
      sk,
      sm2_concat(message, sm2_counter_bytes(current)),
    )
    counter.val = current + 1
    k
  })
  @mooncry.sm2_sig_to_der(signature)
}

///|
/// Verify a DER SM2 signature over `message` with an uncompressed public key
/// (`0x04 || x || y`).
pub fn verify_sm2(
  public_key : Bytes,
  message : Bytes,
  der_signature : Bytes,
) -> Bool {
  let raw = match @mooncry.sm2_sig_from_der(der_signature) {
    Ok(value) => value
    Err(_) => return false
  }
  let id = @utf8.encode("1234567812345678")
  @mooncry.sm2_verify(public_key, message, id, raw)
}

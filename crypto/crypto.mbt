///|
/// Errors raised by the crypto adapters.
pub(all) suberror CryptoError {
  UnsupportedHash(String)
  UnsupportedSignature(String)
  InvalidKey(String)
  InvalidSignatureEncoding
}

///|
/// Digest algorithms supported by MoonSign.
pub(all) enum Hash {
  Sha1
  Sha256
  Sha384
  Sha512
  Sm3
}

///|
/// Dotted OID of the digest algorithm.
pub fn Hash::oid(self : Hash) -> String {
  match self {
    Sha1 => @oids.sha1
    Sha256 => @oids.sha256
    Sha384 => @oids.sha384
    Sha512 => @oids.sha512
    Sm3 => @oids.sm3
  }
}

///|
/// Human-readable name.
pub fn Hash::name(self : Hash) -> String {
  match self {
    Sha1 => "SHA-1"
    Sha256 => "SHA-256"
    Sha384 => "SHA-384"
    Sha512 => "SHA-512"
    Sm3 => "SM3"
  }
}

///|
/// Map a dotted OID to a hash algorithm.
pub fn Hash::from_oid(oid : String) -> Hash? {
  if oid == @oids.sha1 {
    Some(Hash::Sha1)
  } else if oid == @oids.sha256 {
    Some(Hash::Sha256)
  } else if oid == @oids.sha384 {
    Some(Hash::Sha384)
  } else if oid == @oids.sha512 {
    Some(Hash::Sha512)
  } else if oid == @oids.sm3 {
    Some(Hash::Sm3)
  } else {
    None
  }
}

///|
/// Compute a digest.
pub fn digest(hash : Hash, data : Bytes) -> Bytes {
  match hash {
    Sha1 => @mooncry.sha1(data)
    Sha256 => @mooncry.sha256(data)
    Sha384 => @mooncry.sha384(data)
    Sha512 => @mooncry.sha512(data)
    Sm3 => @mooncry.sm3(data)
  }
}

///|
fn strip_leading_zeros(value : Bytes) -> Bytes {
  let mut start = 0
  while start < value.length() && value[start].to_int() == 0 {
    start = start + 1
  }
  let length = value.length() - start
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = value[start + i]
  }
  Bytes::from_array(out[:])
}

///|
fn rsa_hash(hash : Hash) -> @mooncry.RsaHash raise CryptoError {
  match hash {
    Sha1 => @mooncry.rsa_hash_sha1
    Sha256 => @mooncry.rsa_hash_sha256
    Sha384 => @mooncry.rsa_hash_sha384
    Sha512 => @mooncry.rsa_hash_sha512
    Sm3 => raise CryptoError::UnsupportedHash("SM3 is not supported for RSA")
  }
}

///|
/// RSASSA-PKCS1-v1.5 signature over `message` (the message is hashed here).
pub fn sign_rsa_pkcs1(
  hash : Hash,
  message : Bytes,
  modulus : Bytes,
  private_exponent : Bytes,
) -> Bytes raise CryptoError {
  let n = strip_leading_zeros(modulus)
  if n.length() < 64 {
    raise CryptoError::InvalidKey("RSA modulus is too small")
  }
  @mooncry.rsa_pkcs1_v15_sign_with(message, n, private_exponent, rsa_hash(hash))
}

///|
/// Verify an RSASSA-PKCS1-v1.5 signature.
pub fn verify_rsa_pkcs1(
  hash : Hash,
  message : Bytes,
  signature : Bytes,
  modulus : Bytes,
  exponent : Bytes,
) -> Bool {
  let n = strip_leading_zeros(modulus)
  let e = strip_leading_zeros(exponent)
  let h = rsa_hash(hash) catch { _ => return false }
  @mooncry.rsa_pkcs1_v15_verify_with(message, signature, n, e, h)
}

///|
/// ECDSA P-256 signature over `message`, DER-encoded as `SEQUENCE { r, s }`.
///
/// mooncry implements RFC 6979 with SHA-256, so only SHA-256 is accepted.
pub fn sign_ecdsa_p256(
  hash : Hash,
  message : Bytes,
  private_key : Bytes,
) -> Bytes raise CryptoError {
  match hash {
    Sha256 => ()
    _ =>
      raise CryptoError::UnsupportedHash(
        "ECDSA P-256 uses SHA-256 in this build",
      )
  }
  let raw = @mooncry.ecdsa_p256_sign(private_key, message)
  let r = Array::make(32, b'\x00')
  let s = Array::make(32, b'\x00')
  for i in 0..<32 {
    r[i] = raw[i]
    s[i] = raw[32 + i]
  }
  @der.der_sequence([
    @der.der_integer_bytes(Bytes::from_array(r[:])),
    @der.der_integer_bytes(Bytes::from_array(s[:])),
  ])
}

///|
/// Verify a DER-encoded ECDSA P-256 signature.
pub fn verify_ecdsa_p256(
  hash : Hash,
  message : Bytes,
  signature_der : Bytes,
  public_key : Bytes,
) -> Bool {
  match hash {
    Sha256 => ()
    _ => return false
  }
  let reader = @der.DerReader::new(signature_der)
  let seq = reader.read_sequence() catch { _ => return false }
  let r_tlv = seq.read_tlv() catch { _ => return false }
  let s_tlv = seq.read_tlv() catch { _ => return false }
  if r_tlv.tag != @der.tag_integer || s_tlv.tag != @der.tag_integer {
    return false
  }
  let raw = Array::make(64, b'\x00')
  if !copy_padded(r_tlv.content, raw, 0) || !copy_padded(s_tlv.content, raw, 32) {
    return false
  }
  @mooncry.ecdsa_p256_verify(public_key, message, Bytes::from_array(raw[:]))
}

///|
/// Right-align a big-endian magnitude into `out[dst_offset:dst_offset+32]`.
fn copy_padded(value : Bytes, out : Array[Byte], dst_offset : Int32) -> Bool {
  // Strip a sign-padding zero if present.
  let mut start = 0
  if value.length() > 1 && value[0].to_int() == 0 {
    start = 1
  }
  let length = value.length() - start
  if length > 32 {
    return false
  }
  for i in 0..<length {
    out[dst_offset + (32 - length) + i] = value[start + i]
  }
  true
}

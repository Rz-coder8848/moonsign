///|
/// Errors raised while reading PEM files or private keys.
pub(all) suberror PemError {
  NoBlock
  InvalidBase64
  Der(@der.DerError)
  X509(@x509.X509Error)
  UnknownKey(String)
  UnsupportedCurve(String)
  NotPrivateKey
}

///|
/// One PEM block: its label and decoded DER bytes.
pub(all) struct PemBlock {
  label : String
  der : Bytes
}

///|
fn find_bytes(haystack : Bytes, needle : Bytes, from : Int32) -> Int32? {
  let n = needle.length()
  if n == 0 || haystack.length() < n {
    return None
  }
  let mut i = from
  while i + n <= haystack.length() {
    let mut j = 0
    while j < n && haystack[i + j].to_int() == needle[j].to_int() {
      j = j + 1
    }
    if j == n {
      return Some(i)
    }
    i = i + 1
  }
  None
}

///|
fn bytes_of_ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
fn text_of_range(bytes : Bytes, start : Int32, end : Int32) -> String {
  let buf = StringBuilder()
  for i in start..<end {
    buf.write_char(bytes[i].to_char())
  }
  buf.to_string()
}

///|
fn is_space(byte : Byte) -> Bool {
  let value = byte.to_int()
  value == 32 || value == 9 || value == 10 || value == 13
}

///|
/// Parse all PEM blocks in `text`.
///
/// Leading text before the first block and whitespace inside blocks are
/// ignored, which matches the usual `openssl` output.
pub fn parse_pem(text : String) -> Array[PemBlock] raise PemError {
  let bytes = bytes_of_ascii(text)
  let begin_prefix = bytes_of_ascii("-----BEGIN ")

  let dashes = bytes_of_ascii("-----")
  let out : Array[PemBlock] = []
  let mut position = 0
  while true {
    let begin = match find_bytes(bytes, begin_prefix, position) {
      Some(index) => index
      None => break
    }
    let label_start = begin + begin_prefix.length()
    let label_end = match find_bytes(bytes, dashes, label_start) {
      Some(index) => index
      None => raise PemError::NoBlock
    }
    let label = text_of_range(bytes, label_start, label_end)
    let body_start = label_end + dashes.length()
    let end_marker = "-----END " + label + "-----"
    let end_bytes = bytes_of_ascii(end_marker)
    let end_start = match find_bytes(bytes, end_bytes, body_start) {
      Some(index) => index
      None => raise PemError::NoBlock
    }
    let body = StringBuilder()
    for i in body_start..<end_start {
      if !is_space(bytes[i]) {
        body.write_char(bytes[i].to_char())
      }
    }
    let encoded = body.to_string()
    let der = @mooncry.base64_decode(encoded)
    if der.length() == 0 {
      raise PemError::InvalidBase64
    }
    out.push({ label, der, })
    position = end_start + end_bytes.length()
  }
  out
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise PemError {
  reader.read_sequence() catch {
    e => raise PemError::Der(e)
  }
}

///|
fn read_int(reader : @der.DerReader) -> Int32 raise PemError {
  reader.read_integer_int() catch {
    e => raise PemError::Der(e)
  }
}

///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise PemError {
  reader.read_tlv() catch {
    e => raise PemError::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise PemError {
  reader.read_oid() catch {
    e => raise PemError::Der(e)
  }
}

///|
/// A private key that MoonSign can use.
pub(all) enum PrivateKey {
  /// RSA: modulus and private exponent (big-endian magnitudes).
  Rsa(Bytes, Bytes)
  /// ECDSA P-256: 32-byte private scalar.
  EcdsaP256(Bytes)
}

///|
fn parse_pkcs1_rsa(der : Bytes) -> PrivateKey raise PemError {
  let reader = @der.DerReader::new(der)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  let modulus = read_tlv(sequence)
  let _exponent = read_tlv(sequence)
  let private_exponent = read_tlv(sequence)
  if modulus.tag != @der.tag_integer || private_exponent.tag != @der.tag_integer {
    raise PemError::NotPrivateKey
  }
  PrivateKey::Rsa(modulus.content, private_exponent.content)
}

///|
fn parse_ec_private(der : Bytes) -> PrivateKey raise PemError {
  let reader = @der.DerReader::new(der)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  let scalar = read_tlv(sequence)
  if scalar.tag != @der.tag_octet_string {
    raise PemError::NotPrivateKey
  }
  PrivateKey::EcdsaP256(scalar.content)
}

///|
fn parse_pkcs8(der : Bytes) -> PrivateKey raise PemError {
  let reader = @der.DerReader::new(der)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  let algorithm = read_seq(sequence)
  let algorithm_oid = read_oid(algorithm)
  let params = if algorithm.is_empty() {
    None
  } else {
    Some(read_tlv(algorithm).raw)
  }
  let key = read_tlv(sequence)
  if key.tag != @der.tag_octet_string {
    raise PemError::NotPrivateKey
  }
  if algorithm_oid == @oids.rsa_encryption {
    parse_pkcs1_rsa(key.content)
  } else if algorithm_oid == @oids.ec_public_key || algorithm_oid == @oids.sm2 {
    match params {
      Some(raw) => {
        let param_reader = @der.DerReader::new(raw)
        let param = read_tlv(param_reader)
        if param.tag == @der.tag_oid {
          let curve = @der.decode_oid(param.content) catch {
            e => raise PemError::Der(e)
          }
          if curve != @oids.curve_p256 && curve != @oids.sm2 {
            raise PemError::UnsupportedCurve(curve)
          }
        }
      }
      None => ()
    }
    parse_ec_private(key.content)
  } else {
    raise PemError::UnknownKey(algorithm_oid)
  }
}

///|
/// Parse a DER private key in PKCS#8, PKCS#1 (RSA) or SEC1 (EC) form.
pub fn parse_private_key(der : Bytes) -> PrivateKey raise PemError {
  let reader = @der.DerReader::new(der)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  match sequence.peek_tag() {
    Some(tag) =>
      if tag == 0x30 {
        parse_pkcs8(der)
      } else if tag == 0x02 {
        parse_pkcs1_rsa(der)
      } else if tag == 0x04 {
        parse_ec_private(der)
      } else {
        raise PemError::NotPrivateKey
      }
    None => raise PemError::NotPrivateKey
  }
}

///|
/// Parse every `CERTIFICATE` block in a PEM file (leaf first, as written).
pub fn parse_certificates(
  text : String,
) -> Array[@x509.Certificate] raise PemError {
  let blocks = parse_pem(text)
  let out : Array[@x509.Certificate] = []
  for block in blocks {
    if block.label == "CERTIFICATE" {
      let cert = @x509.parse_certificate(block.der) catch {
        e => raise PemError::X509(e)
      }
      out.push(cert)
    }
  }
  out
}

///|
/// Human-readable description of a PEM/private-key error.
pub fn PemError::message(self : PemError) -> String {
  match self {
    NoBlock => "no PEM block found"
    InvalidBase64 => "invalid base64 in PEM body"
    Der(detail) => "DER error: \{detail.message()}"
    X509(detail) => "X.509 error: \{detail.message()}"
    UnknownKey(oid) => "unsupported private key algorithm: \{oid}"
    UnsupportedCurve(oid) => "unsupported elliptic curve: \{oid}"
    NotPrivateKey => "not a supported private key"
  }
}

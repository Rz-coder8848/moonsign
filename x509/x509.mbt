///|
/// Errors raised while parsing X.509 certificates.
pub(all) suberror X509Error {
  Der(@der.DerError)
  NotACertificate
  MissingField(String)
  BadPublicKey
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise X509Error {
  reader.read_sequence() catch {
    e => raise X509Error::Der(e)
  }
}

///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise X509Error {
  reader.read_tlv() catch {
    e => raise X509Error::Der(e)
  }
}

///|
fn read_expected(
  reader : @der.DerReader,
  tag : Int32,
) -> @der.Tlv raise X509Error {
  reader.read_expected(tag) catch {
    e => raise X509Error::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise X509Error {
  reader.read_oid() catch {
    e => raise X509Error::Der(e)
  }
}

///|
/// A parsed X.509 certificate.
///
/// Raw DER fields are kept so they can be embedded into CMS structures without
/// re-encoding (re-encoding risks byte-level differences).
pub(all) struct Certificate {
  der : Bytes
  tbs_raw : Bytes
  serial_raw : Bytes
  issuer_raw : Bytes
  subject_raw : Bytes
  not_before : Int64
  not_after : Int64
  spki_algorithm_oid : String
  spki_params_raw : Bytes?
  public_key_bits : Bytes
  signature_algorithm_oid : String
  signature_bits : Bytes
}

///|
fn parse_algorithm_identifier(
  reader : @der.DerReader,
) -> (String, Bytes?) raise X509Error {
  let seq = read_seq(reader)
  let oid = read_oid(seq)
  let params = if seq.is_empty() { None } else { Some(read_tlv(seq).raw) }
  (oid, params)
}

///|
/// Parse a DER-encoded X.509 certificate.
pub fn parse_certificate(der : Bytes) -> Certificate raise X509Error {
  let outer = @der.DerReader::new(der)
  let certificate = read_seq(outer)
  let tbs = read_tlv(certificate)
  if tbs.tag != @der.tag_sequence {
    raise X509Error::NotACertificate
  }
  let signature_algorithm = parse_algorithm_identifier(certificate)
  let signature_value = read_expected(certificate, @der.tag_bit_string)

  let tbs_reader = @der.DerReader::at(tbs.content, 0, tbs.content.length()) catch {
    e => raise X509Error::Der(e)
  }
  // version [0] EXPLICIT INTEGER DEFAULT v1
  match tbs_reader.peek_tag() {
    Some(tag) =>
      if tag == 0xA0 {
        let version = read_tlv(tbs_reader)
        let inner = @der.DerReader::at(
          version.content,
          0,
          version.content.length(),
        ) catch {
          e => raise X509Error::Der(e)
        }
        let _ = inner.read_integer_int() catch { e => raise X509Error::Der(e) }
      }
    None => raise X509Error::NotACertificate
  }
  let serial = read_expected(tbs_reader, @der.tag_integer)
  let _signature = parse_algorithm_identifier(tbs_reader)
  let issuer = read_expected(tbs_reader, @der.tag_sequence)
  let validity = read_seq(tbs_reader)
  let not_before_tlv = read_tlv(validity)
  let not_before = @der.der_time_parse(not_before_tlv) catch {
    e => raise X509Error::Der(e)
  }
  let not_after_tlv = read_tlv(validity)
  let not_after = @der.der_time_parse(not_after_tlv) catch {
    e => raise X509Error::Der(e)
  }
  let subject = read_expected(tbs_reader, @der.tag_sequence)
  let spki = read_seq(tbs_reader)
  let (spki_algorithm_oid, spki_params_raw) = parse_algorithm_identifier(spki)
  let bits = read_expected(spki, @der.tag_bit_string)
  if bits.content.length() < 1 {
    raise X509Error::BadPublicKey
  }
  // The first content octet is the number of unused bits; certificates use 0.
  let key_len = bits.content.length() - 1
  let key_bytes = Array::make(key_len, b'\x00')
  for i in 0..<key_len {
    key_bytes[i] = bits.content[i + 1]
  }
  {
    der,
    tbs_raw: tbs.raw,
    serial_raw: serial.raw,
    issuer_raw: issuer.raw,
    subject_raw: subject.raw,
    not_before,
    not_after,
    spki_algorithm_oid,
    spki_params_raw,
    public_key_bits: Bytes::from_array(key_bytes[:]),
    signature_algorithm_oid: signature_algorithm.0,
    signature_bits: signature_value.content,
  }
}

///|
/// Whether the certificate is within its validity window at `unix`.
pub fn Certificate::is_valid_at(self : Certificate, unix : Int64) -> Bool {
  unix >= self.not_before && unix <= self.not_after
}

///|
/// Named curve OID for EC keys, when present.
pub fn Certificate::curve_oid(self : Certificate) -> String? {
  match self.spki_params_raw {
    Some(raw) => {
      let reader = @der.DerReader::new(raw)
      let tlv = reader.read_tlv() catch { _ => return None }
      if tlv.tag == @der.tag_oid {
        let decoded = @der.decode_oid(tlv.content) catch { _ => return None }
        Some(decoded)
      } else {
        None
      }
    }
    None => None
  }
}

///|
/// RSA public key as `(modulus, exponent)` big-endian magnitudes.
///
/// The modulus may carry a leading zero octet from its DER INTEGER encoding;
/// callers that need the exact modulus length must strip it.
pub fn Certificate::rsa_public_key(self : Certificate) -> (Bytes, Bytes)? {
  if self.spki_algorithm_oid != @oids.rsa_encryption {
    return None
  }
  let reader = @der.DerReader::new(self.public_key_bits)
  let seq = reader.read_sequence() catch { _ => return None }
  let modulus = seq.read_tlv() catch { _ => return None }
  let exponent = seq.read_tlv() catch { _ => return None }
  if modulus.tag != @der.tag_integer || exponent.tag != @der.tag_integer {
    return None
  }
  Some((modulus.content, exponent.content))
}

///|
/// EC public key as an uncompressed point (`0x04 || X || Y`).
pub fn Certificate::ec_public_key(self : Certificate) -> Bytes? {
  if self.spki_algorithm_oid != @oids.ec_public_key {
    return None
  }
  Some(self.public_key_bits)
}

///|
/// Human-readable description of an X.509 error.
pub fn X509Error::message(self : X509Error) -> String {
  match self {
    Der(detail) => "DER error: \{detail.message()}"
    NotACertificate => "input is not an X.509 certificate"
    MissingField(field) => "missing or malformed field: \{field}"
    BadPublicKey => "malformed public key"
  }
}

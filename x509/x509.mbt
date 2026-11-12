///|
/// Errors raised while parsing X.509 certificates.
pub(all) suberror X509Error {
  Der(@der.DerError)
  NotACertificate
  NotACrl
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
fn read_int(reader : @der.DerReader) -> Int32 raise X509Error {
  reader.read_integer_int() catch {
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
  is_ca : Bool
  path_len : Int32?
  key_cert_sign : Bool
  has_key_usage : Bool
  subject_key_id : Bytes?
  authority_key_id : Bytes?
  extended_key_usage : Array[String]
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

///|
fn parse_extended_key_usage(bytes : Bytes) -> Array[String] raise X509Error {
  let reader = @der.DerReader::new(bytes)
  let sequence = read_seq(reader)
  let out : Array[String] = []
  while !sequence.is_empty() {
    out.push(read_oid(sequence))
  }
  out
}

///|
fn parse_basic_constraints(bytes : Bytes) -> (Bool, Int32?) raise X509Error {
  let reader = @der.DerReader::new(bytes)
  let sequence = read_seq(reader)
  let mut is_ca = false
  let mut path_len : Int32? = None
  match sequence.peek_tag() {
    Some(tag) =>
      if tag == 0x01 {
        let value = read_tlv(sequence)
        is_ca = value.content.length() > 0 && value.content[0].to_int() != 0
      }
    None => ()
  }
  match sequence.peek_tag() {
    Some(tag) => if tag == 0x02 { path_len = Some(read_int(sequence)) }
    None => ()
  }
  (is_ca, path_len)
}

///|
fn parse_key_usage(bytes : Bytes) -> Bool raise X509Error {
  let reader = @der.DerReader::new(bytes)
  let bits = read_expected(reader, @der.tag_bit_string)
  if bits.content.length() < 2 {
    return false
  }
  // KeyUsage bit 5 is keyCertSign; bits are MSB-first in the first data octet.
  (bits.content[1].to_int() & 0x04) != 0
}

///|
fn parse_subject_key_identifier(bytes : Bytes) -> Bytes? raise X509Error {
  let reader = @der.DerReader::new(bytes)
  let value = read_expected(reader, @der.tag_octet_string)
  Some(value.content)
}

///|
fn parse_authority_key_identifier(bytes : Bytes) -> Bytes? raise X509Error {
  let reader = @der.DerReader::new(bytes)
  let sequence = read_seq(reader)
  while !sequence.is_empty() {
    let value = read_tlv(sequence)
    if value.tag == 0x80 {
      return Some(value.content)
    }
  }
  None
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
  let mut is_ca = false
  let mut path_len : Int32? = None
  let mut key_cert_sign = false
  let mut has_key_usage = false
  let mut subject_key_id : Bytes? = None
  let mut authority_key_id : Bytes? = None
  let mut extended_key_usage : Array[String] = []
  match tbs_reader.peek_tag() {
    Some(tag) =>
      if tag == 0xA3 {
        let wrapper = read_tlv(tbs_reader)
        let extension_reader = @der.DerReader::at(
          wrapper.content,
          0,
          wrapper.content.length(),
        ) catch {
          e => raise X509Error::Der(e)
        }
        let extensions = read_seq(extension_reader)
        while !extensions.is_empty() {
          let extension = read_seq(extensions)
          let oid = read_oid(extension)
          match extension.peek_tag() {
            Some(1) => {
              let _ = read_tlv(extension)
            }
            _ => ()
          }
          let value = read_expected(extension, @der.tag_octet_string)
          if oid == @oids.basic_constraints {
            let (ca, limit) = parse_basic_constraints(value.content)
            is_ca = ca
            path_len = limit
          } else if oid == @oids.key_usage {
            has_key_usage = true
            key_cert_sign = parse_key_usage(value.content)
          } else if oid == @oids.subject_key_identifier {
            subject_key_id = parse_subject_key_identifier(value.content)
          } else if oid == @oids.authority_key_identifier {
            authority_key_id = parse_authority_key_identifier(value.content)
          } else if oid == @oids.extended_key_usage {
            extended_key_usage = parse_extended_key_usage(value.content)
          }
        }
      }
    None => ()
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
    is_ca,
    path_len,
    key_cert_sign,
    has_key_usage,
    subject_key_id,
    authority_key_id,
    extended_key_usage,
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
/// Decode a DirectoryString value from an X.509 name.
fn decode_directory_string(value : @der.Tlv) -> String {
  match value.tag {
    0x0C => @utf8.decode_lossy(value.content)
    0x13 | 0x16 => {
      let buf = StringBuilder()
      for i in 0..<value.content.length() {
        buf.write_char(value.content[i].to_char())
      }
      buf.to_string()
    }
    0x1E => {
      let buf = StringBuilder()
      let mut i = 0
      while i + 1 < value.content.length() {
        let code = value.content[i].to_int() * 256 +
          value.content[i + 1].to_int()
        if code > 0 {
          match code.to_char() {
            Some(ch) => buf.write_char(ch)
            None => ()
          }
        }
        i = i + 2
      }
      buf.to_string()
    }
    _ => ""
  }
}

///|
/// The first Common Name (CN) in the subject, if present.
pub fn Certificate::common_name(self : Certificate) -> String? {
  let reader = @der.DerReader::new(self.subject_raw)
  let name = read_seq(reader) catch { _ => return None }
  while !name.is_empty() {
    let rdn_tlv = read_tlv(name) catch { _ => return None }
    if rdn_tlv.tag == 0x31 {
      let rdn_reader = @der.DerReader::at(
        rdn_tlv.content,
        0,
        rdn_tlv.content.length(),
      ) catch {
        _ => return None
      }
      while !rdn_reader.is_empty() {
        let attribute = read_seq(rdn_reader) catch { _ => return None }
        let oid = read_oid(attribute) catch { _ => return None }
        let value = read_tlv(attribute) catch { _ => return None }
        if oid == "2.5.4.3" {
          return Some(decode_directory_string(value))
        }
      }
    }
  }
  None
}

///|
/// Whether the certificate lists `oid` in its Extended Key Usage extension.
pub fn Certificate::has_extended_key_usage(
  self : Certificate,
  oid : String,
) -> Bool {
  for item in self.extended_key_usage {
    if item == oid {
      return true
    }
  }
  false
}

///|
/// Whether the subject and issuer names are identical (self-issued).
pub fn Certificate::is_self_issued(self : Certificate) -> Bool {
  @der.der_bytes_compare(self.subject_raw, self.issuer_raw) == 0
}

///|
fn is_rsa_signature(oid : String) -> Bool {
  oid == @oids.sha1_with_rsa ||
  oid == @oids.sha256_with_rsa ||
  oid == @oids.sha384_with_rsa ||
  oid == @oids.sha512_with_rsa
}

///|
fn is_ecdsa_signature(oid : String) -> Bool {
  oid == @oids.ecdsa_with_sha256 ||
  oid == @oids.ecdsa_with_sha384 ||
  oid == @oids.ecdsa_with_sha512
}

///|
fn signature_hash(oid : String) -> @crypto.Hash? {
  if oid == @oids.sha1_with_rsa {
    Some(@crypto.Hash::Sha1)
  } else if oid == @oids.sha256_with_rsa || oid == @oids.ecdsa_with_sha256 {
    Some(@crypto.Hash::Sha256)
  } else if oid == @oids.sha384_with_rsa {
    Some(@crypto.Hash::Sha384)
  } else if oid == @oids.sha512_with_rsa {
    Some(@crypto.Hash::Sha512)
  } else {
    None
  }
}

///|
/// Verify that `cert` was signed by `issuer`.
///
/// This checks the certificate signature only; validity, CA status and name
/// chaining are the caller's job (see the `trust` package).

///|
fn verify_signed_bytes(
  algorithm_oid : String,
  signed_bytes : Bytes,
  signature_bits : Bytes,
  issuer : Certificate,
) -> Bool {
  let hash = match signature_hash(algorithm_oid) {
    Some(value) => value
    None => return false
  }
  if signature_bits.length() < 2 {
    return false
  }
  let signature_length = signature_bits.length() - 1
  let signature = Array::make(signature_length, b'\x00')
  for i in 0..<signature_length {
    signature[i] = signature_bits[i + 1]
  }
  let signature_bytes = Bytes::from_array(signature[:])
  if is_rsa_signature(algorithm_oid) {
    match issuer.rsa_public_key() {
      Some((modulus, exponent)) =>
        @crypto.verify_rsa_pkcs1(
          hash, signed_bytes, signature_bytes, modulus, exponent,
        )
      None => false
    }
  } else if is_ecdsa_signature(algorithm_oid) {
    match issuer.ec_public_key() {
      Some(point) =>
        @crypto.verify_ecdsa_p256(hash, signed_bytes, signature_bytes, point)
      None => false
    }
  } else {
    false
  }
}

///|
/// Verify a signature over arbitrary bytes with a certificate's public key.
pub fn verify_signature(
  algorithm_oid : String,
  signed_bytes : Bytes,
  signature_bits : Bytes,
  certificate : Certificate,
) -> Bool {
  verify_signed_bytes(algorithm_oid, signed_bytes, signature_bits, certificate)
}

///|
/// Verify that `cert` was signed by `issuer`.
///
/// This checks the certificate signature only; validity, CA status and name
/// chaining are the caller's job (see the `trust` package).
pub fn verify_certificate_signature(
  cert : Certificate,
  issuer : Certificate,
) -> Bool {
  verify_signed_bytes(
    cert.signature_algorithm_oid,
    cert.tbs_raw,
    cert.signature_bits,
    issuer,
  )
}

///|
/// A parsed X.509 certificate revocation list.
pub(all) struct Crl {
  der : Bytes
  tbs_raw : Bytes
  issuer_raw : Bytes
  this_update : Int64
  next_update : Int64?
  revoked_serials : Array[Bytes]
  signature_algorithm_oid : String
  signature_bits : Bytes
}

///|
/// Parse a DER-encoded X.509 CRL.
pub fn parse_crl(der : Bytes) -> Crl raise X509Error {
  let outer = @der.DerReader::new(der)
  let list = read_seq(outer)
  let tbs = read_tlv(list)
  if tbs.tag != @der.tag_sequence {
    raise X509Error::NotACrl
  }
  let signature_algorithm = parse_algorithm_identifier(list)
  let signature_value = read_expected(list, @der.tag_bit_string)
  let tbs_reader = @der.DerReader::at(tbs.content, 0, tbs.content.length()) catch {
    e => raise X509Error::Der(e)
  }
  match tbs_reader.peek_tag() {
    Some(tag) => if tag == @der.tag_integer { let _ = read_tlv(tbs_reader) }
    None => ()
  }
  let _signature = parse_algorithm_identifier(tbs_reader)
  let issuer = read_expected(tbs_reader, @der.tag_sequence)
  let this_update_tlv = read_tlv(tbs_reader)
  let this_update = @der.der_time_parse(this_update_tlv) catch {
    e => raise X509Error::Der(e)
  }
  let mut next_update : Int64? = None
  match tbs_reader.peek_tag() {
    Some(tag) =>
      if tag == @der.tag_utc_time || tag == @der.tag_generalized_time {
        let next_tlv = read_tlv(tbs_reader)
        let parsed = @der.der_time_parse(next_tlv) catch {
          e => raise X509Error::Der(e)
        }
        next_update = Some(parsed)
      }
    None => ()
  }
  let revoked : Array[Bytes] = []
  match tbs_reader.peek_tag() {
    Some(tag) =>
      if tag == @der.tag_sequence {
        let entries = read_seq(tbs_reader)
        while !entries.is_empty() {
          let entry = read_seq(entries)
          let serial = read_expected(entry, @der.tag_integer)
          revoked.push(serial.content)
          let _date = read_tlv(entry)
        }
      }
    None => ()
  }
  {
    der,
    tbs_raw: tbs.raw,
    issuer_raw: issuer.raw,
    this_update,
    next_update,
    revoked_serials: revoked,
    signature_algorithm_oid: signature_algorithm.0,
    signature_bits: signature_value.content,
  }
}

///|
fn serial_content(serial : Bytes) -> Bytes {
  // Certificate serials are stored as the full INTEGER TLV; CRL entries are
  // stored as content octets. Normalise both to content octets.
  if serial.length() > 2 && serial[0].to_int() == 2 {
    let length = serial[1].to_int()
    if length < 128 && 2 + length <= serial.length() {
      let out = Array::make(length, b'\x00')
      for i in 0..<length {
        out[i] = serial[2 + i]
      }
      return Bytes::from_array(out[:])
    }
  }
  serial
}

///|
fn normalize_serial(serial : Bytes) -> Bytes {
  let mut start = 0
  while start < serial.length() && serial[start].to_int() == 0 {
    start = start + 1
  }
  let length = serial.length() - start
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = serial[start + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Whether the given serial number appears in the CRL.
pub fn Crl::is_revoked(self : Crl, serial_raw : Bytes) -> Bool {
  let target = normalize_serial(serial_content(serial_raw))
  for revoked in self.revoked_serials {
    if @der.der_bytes_compare(normalize_serial(serial_content(revoked)), target) ==
      0 {
      return true
    }
  }
  false
}

///|
/// Verify the CRL signature with the issuer certificate.
pub fn verify_crl_signature(crl : Crl, issuer : Certificate) -> Bool {
  verify_signed_bytes(
    crl.signature_algorithm_oid,
    crl.tbs_raw,
    crl.signature_bits,
    issuer,
  )
}

///|
/// Human-readable description of an X.509 error.
pub fn X509Error::message(self : X509Error) -> String {
  match self {
    Der(detail) => "DER error: \{detail.message()}"
    NotACertificate => "input is not an X.509 certificate"
    NotACrl => "input is not an X.509 CRL"
    MissingField(field) => "missing or malformed field: \{field}"
    BadPublicKey => "malformed public key"
  }
}

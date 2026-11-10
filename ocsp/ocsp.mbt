///|
/// Errors raised while parsing or checking an OCSP response.
pub(all) suberror OcspError {
  Der(@der.DerError)
  X509(@x509.X509Error)
  BadResponse(String)
  NoResponse
  CertMismatch
  Stale
  SignatureInvalid
  Unsupported(String)
}

///|
/// Certificate status from an OCSP SingleResponse.
pub(all) enum CertStatus {
  Good
  Revoked(Int64)
  Unknown
}

///|
/// One SingleResponse inside an OCSP response.
pub(all) struct SingleResponse {
  hash_oid : String
  issuer_name_hash : Bytes
  issuer_key_hash : Bytes
  serial : Bytes
  status : CertStatus
  this_update : Int64
  next_update : Int64?
}

///|
/// Parsed OCSPResponse (only the successful case carries data).
pub(all) struct OcspResponse {
  status : Int32
  responses : Array[SingleResponse]
  certificates : Array[@x509.Certificate]
  tbs_raw : Bytes
  signature_algorithm_oid : String
  signature_bits : Bytes
}

///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise OcspError {
  reader.read_tlv() catch {
    e => raise OcspError::Der(e)
  }
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise OcspError {
  reader.read_sequence() catch {
    e => raise OcspError::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise OcspError {
  reader.read_oid() catch {
    e => raise OcspError::Der(e)
  }
}

///|
fn reader_at(bytes : Bytes) -> @der.DerReader raise OcspError {
  @der.DerReader::at(bytes, 0, bytes.length()) catch {
    e => raise OcspError::Der(e)
  }
}

///|
fn read_enumerated_int(reader : @der.DerReader) -> Int32 raise OcspError {
  let value = read_tlv(reader)
  if value.tag != 0x0A {
    raise OcspError::BadResponse("responseStatus is not an ENUMERATED")
  }
  let mut result = 0
  for i in 0..<value.content.length() {
    result = result * 256 + value.content[i].to_int()
  }
  result
}

///|
fn serial_content(serial : Bytes) -> Bytes {
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
fn strip_zeros(serial : Bytes) -> Bytes {
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
fn parse_single_response(
  reader : @der.DerReader,
) -> SingleResponse raise OcspError {
  let sequence = read_seq(reader)
  let cert_id = read_seq(sequence)
  let algorithm = read_seq(cert_id)
  let hash_oid = read_oid(algorithm)
  let name_hash = read_tlv(cert_id)
  if name_hash.tag != @der.tag_octet_string {
    raise OcspError::BadResponse("issuerNameHash is not an OCTET STRING")
  }
  let key_hash = read_tlv(cert_id)
  if key_hash.tag != @der.tag_octet_string {
    raise OcspError::BadResponse("issuerKeyHash is not an OCTET STRING")
  }
  let serial = read_tlv(cert_id)
  if serial.tag != @der.tag_integer {
    raise OcspError::BadResponse("serialNumber is not an INTEGER")
  }
  let status_tlv = read_tlv(sequence)
  let status = match status_tlv.tag {
    0x80 => CertStatus::Good
    0xA1 => {
      let inner = reader_at(status_tlv.content)
      let time_tlv = read_tlv(inner)
      let revoked_at = @der.der_time_parse(time_tlv) catch {
        e => raise OcspError::Der(e)
      }
      CertStatus::Revoked(revoked_at)
    }
    0x82 => CertStatus::Unknown
    _ => raise OcspError::BadResponse("unknown certificate status tag")
  }
  let this_tlv = read_tlv(sequence)
  let this_update = @der.der_time_parse(this_tlv) catch {
    e => raise OcspError::Der(e)
  }
  let mut next_update : Int64? = None
  match sequence.peek_tag() {
    Some(tag) =>
      if tag == 0xA0 {
        let wrapper = read_tlv(sequence)
        let inner = reader_at(wrapper.content)
        let next_tlv = read_tlv(inner)
        let parsed = @der.der_time_parse(next_tlv) catch {
          e => raise OcspError::Der(e)
        }
        next_update = Some(parsed)
      }
    None => ()
  }
  {
    hash_oid,
    issuer_name_hash: name_hash.content,
    issuer_key_hash: key_hash.content,
    serial: serial.content,
    status,
    this_update,
    next_update,
  }
}

///|
fn parse_basic_response(bytes : Bytes) -> OcspResponse raise OcspError {
  let reader = reader_at(bytes)
  let basic = read_seq(reader)
  let tbs = read_tlv(basic)
  if tbs.tag != @der.tag_sequence {
    raise OcspError::BadResponse("tbsResponseData is not a SEQUENCE")
  }
  let algorithm = read_seq(basic)
  let signature_oid = read_oid(algorithm)
  let signature = read_tlv(basic)
  if signature.tag != @der.tag_bit_string {
    raise OcspError::BadResponse("response signature is not a BIT STRING")
  }
  let certificates : Array[@x509.Certificate] = []
  match basic.peek_tag() {
    Some(tag) =>
      if tag == 0xA0 {
        let wrapper = read_tlv(basic)
        let certs_reader = reader_at(wrapper.content)
        let certs = read_seq(certs_reader)
        while !certs.is_empty() {
          let cert_tlv = read_tlv(certs)
          let cert = @x509.parse_certificate(cert_tlv.raw) catch {
            e => raise OcspError::X509(e)
          }
          certificates.push(cert)
        }
      }
    None => ()
  }
  let tbs_reader = reader_at(tbs.content)
  match tbs_reader.peek_tag() {
    Some(tag) => if tag == 0xA0 { let _ = read_tlv(tbs_reader) }
    None => ()
  }
  let _responder_id = read_tlv(tbs_reader)
  let _produced_at = read_tlv(tbs_reader)
  let responses_sequence = read_seq(tbs_reader)
  let responses : Array[SingleResponse] = []
  while !responses_sequence.is_empty() {
    responses.push(parse_single_response(responses_sequence))
  }
  {
    status: 0,
    responses,
    certificates,
    tbs_raw: tbs.raw,
    signature_algorithm_oid: signature_oid,
    signature_bits: signature.content,
  }
}

///|
/// Parse a DER-encoded OCSPResponse.
pub fn parse_response(bytes : Bytes) -> OcspResponse raise OcspError {
  let reader = reader_at(bytes)
  let outer = read_seq(reader)
  let status = read_enumerated_int(outer)
  if status != 0 {
    return {
      status,
      responses: [],
      certificates: [],
      tbs_raw: b"",
      signature_algorithm_oid: "",
      signature_bits: b"",
    }
  }
  let wrapper = read_tlv(outer)
  if wrapper.tag != 0xA0 {
    raise OcspError::BadResponse("responseBytes is missing")
  }
  let response_bytes = reader_at(wrapper.content)
  let response_sequence = read_seq(response_bytes)
  let response_type = read_oid(response_sequence)
  if response_type != "1.3.6.1.5.5.7.48.1.1" {
    raise OcspError::Unsupported(
      "unsupported OCSP response type: " + response_type,
    )
  }
  let basic = read_tlv(response_sequence)
  if basic.tag != @der.tag_octet_string {
    raise OcspError::BadResponse("BasicOCSPResponse is not an OCTET STRING")
  }
  parse_basic_response(basic.content)
}

///|
/// Check `cert` against the OCSP response. `issuer` must be the certificate
/// that issued `cert`. The response signature is checked with the included
/// responder certificate (or the issuer itself).
pub fn check(
  response : OcspResponse,
  cert : @x509.Certificate,
  issuer : @x509.Certificate,
  at_time : Int64,
) -> CertStatus raise OcspError {
  if response.status != 0 {
    raise OcspError::NoResponse
  }
  let serial = serial_content(cert.serial_raw)
  let mut match_response : SingleResponse? = None
  for single in response.responses {
    let hash = match @crypto.Hash::from_oid(single.hash_oid) {
      Some(value) => value
      None => continue
    }
    let name_hash = @crypto.digest(hash, issuer.subject_raw)
    let key_hash = @crypto.digest(hash, issuer.public_key_bits)
    if @der.der_bytes_compare(name_hash, single.issuer_name_hash) != 0 {
      continue
    }
    if @der.der_bytes_compare(key_hash, single.issuer_key_hash) != 0 {
      continue
    }
    if @der.der_bytes_compare(strip_zeros(serial), strip_zeros(single.serial)) !=
      0 {
      continue
    }
    match_response = Some(single)
  }
  let single = match match_response {
    Some(value) => value
    None => raise OcspError::CertMismatch
  }
  if at_time < single.this_update {
    raise OcspError::Stale
  }
  match single.next_update {
    Some(next) => if at_time > next { raise OcspError::Stale }
    None => ()
  }
  let mut signer : @x509.Certificate? = None
  for candidate in response.certificates {
    let valid = @x509.verify_signature(
      response.signature_algorithm_oid,
      response.tbs_raw,
      response.signature_bits,
      candidate,
    )
    if valid {
      signer = Some(candidate)
    }
  }
  if signer is None &&
    @x509.verify_signature(
      response.signature_algorithm_oid,
      response.tbs_raw,
      response.signature_bits,
      issuer,
    ) {
    signer = Some(issuer)
  }
  let responder = match signer {
    Some(value) => value
    None => raise OcspError::SignatureInvalid
  }
  if @der.der_bytes_compare(responder.der, issuer.der) != 0 &&
    !responder.has_extended_key_usage(@oids.id_kp_ocsp_signing) {
    raise OcspError::Unsupported(
      "responder certificate lacks the OCSPSigning EKU",
    )
  }
  single.status
}

///|
/// Human-readable description of an OCSP error.
pub fn OcspError::message(self : OcspError) -> String {
  match self {
    Der(detail) => "DER error: \{detail.message()}"
    X509(detail) => "certificate error: \{detail.message()}"
    BadResponse(detail) => "bad OCSP response: \{detail}"
    NoResponse => "OCSP responder returned an error status"
    CertMismatch => "OCSP response does not cover this certificate"
    Stale => "OCSP response is outside its validity window"
    SignatureInvalid => "OCSP response signature does not verify"
    Unsupported(detail) => "unsupported OCSP feature: \{detail}"
  }
}

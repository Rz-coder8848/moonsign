///|
/// Errors raised by the RFC 3161 timestamp helpers.
pub(all) suberror TsaError {
  Der(@der.DerError)
  Cms(@cms.CmsError)
  BadResponse(String)
  Trust(String)
  NoToken
  Status(Int32)
  ImprintMismatch
}

///|
/// A parsed TimeStampResp.
pub(all) struct TsaResponse {
  status : Int32
  token : Bytes?
  failure : String?
}

///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise TsaError {
  reader.read_tlv() catch {
    e => raise TsaError::Der(e)
  }
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise TsaError {
  reader.read_sequence() catch {
    e => raise TsaError::Der(e)
  }
}

///|
fn read_int(reader : @der.DerReader) -> Int32 raise TsaError {
  reader.read_integer_int() catch {
    e => raise TsaError::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise TsaError {
  reader.read_oid() catch {
    e => raise TsaError::Der(e)
  }
}

///|
fn reader_at(bytes : Bytes) -> @der.DerReader raise TsaError {
  @der.DerReader::at(bytes, 0, bytes.length()) catch {
    e => raise TsaError::Der(e)
  }
}

///|
/// Build a DER-encoded TimeStampReq for `signature` (the CMS signature value).
pub fn build_request(
  signature : Bytes,
  hash : @crypto.Hash,
  include_cert : Bool,
) -> Bytes {
  let message_imprint = @der.der_sequence([
    @der.der_sequence([@oids.encode(hash.oid())]),
    @der.der_octet_string(@crypto.digest(hash, signature)),
  ])
  let parts : Array[Bytes] = [@der.der_integer_int(1), message_imprint]
  if include_cert {
    parts.push(@der.der_boolean(true))
  }
  @der.der_sequence(parts)
}

///|
/// Extract `(digest_oid, hashed_message)` from a TimeStampReq.
pub fn request_imprint(request : Bytes) -> (String, Bytes) raise TsaError {
  let reader = reader_at(request)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  let imprint = read_seq(sequence)
  let algorithm = read_seq(imprint)
  let oid = read_oid(algorithm)
  let hashed = read_tlv(imprint)
  if hashed.tag != @der.tag_octet_string {
    raise TsaError::BadResponse("messageImprint is not an OCTET STRING")
  }
  (oid, hashed.content)
}

///|
/// Parse a DER-encoded TimeStampResp.
pub fn parse_response(response : Bytes) -> TsaResponse raise TsaError {
  let reader = reader_at(response)
  let sequence = read_seq(reader)
  let status_info = read_seq(sequence)
  let status = read_int(status_info)
  let mut failure : String? = None
  if !status_info.is_empty() {
    failure = Some("timestamp authority reported an error")
  }
  let token = if sequence.is_empty() {
    None
  } else {
    Some(read_tlv(sequence).raw)
  }
  { status, token, failure, }
}

///|
/// Wrap a TimeStampToken into a successful TimeStampResp.
pub fn wrap_response(token : Bytes) -> Bytes {
  @der.der_sequence([@der.der_sequence([@der.der_integer_int(0)]), token])
}

///|
/// Extract `(digest_oid, hashed_message)` from a TimeStampToken.
///
/// The token is a CMS SignedData whose eContent is a TSTInfo structure.
pub fn token_imprint(token : Bytes) -> (String, Bytes) raise TsaError {
  let signed_data = @cms.parse_signed_data(token) catch {
    e => raise TsaError::Cms(e)
  }
  let content = match signed_data.econtent {
    Some(value) => value
    None => raise TsaError::BadResponse("timestamp token has no eContent")
  }
  let reader = reader_at(content)
  let tst_info = read_seq(reader)
  let _version = read_int(tst_info)
  let _policy = read_oid(tst_info)
  let imprint = read_seq(tst_info)
  let algorithm = read_seq(imprint)
  let oid = read_oid(algorithm)
  let hashed = read_tlv(imprint)
  if hashed.tag != @der.tag_octet_string {
    raise TsaError::BadResponse("messageImprint is not an OCTET STRING")
  }
  (oid, hashed.content)
}

///|
/// Check that `token` timestamps exactly `signature` with `hash`.
pub fn verify_token(
  token : Bytes,
  signature : Bytes,
  hash : @crypto.Hash,
) -> Bool {
  let imprint = token_imprint(token) catch { _ => return false }
  let (oid, hashed) = imprint
  if oid != hash.oid() {
    return false
  }
  @der.der_bytes_compare(hashed, @crypto.digest(hash, signature)) == 0
}

///|
/// Human-readable description of a TSA error.
pub fn TsaError::message(self : TsaError) -> String {
  match self {
    Der(detail) => "DER error: \{detail.message()}"
    Cms(detail) => "CMS error: \{detail.message()}"
    BadResponse(detail) => "bad timestamp response: \{detail}"
    Trust(detail) => "timestamp trust error: \{detail}"
    NoToken => "timestamp response contains no token"
    Status(code) => "timestamp authority returned status \{code}"
    ImprintMismatch => "timestamp token does not match the signature"
  }
}

///|
/// Verify the CMS signature inside a TimeStampToken and return its signer.
pub fn verify_token_signature(token : Bytes) -> @x509.Certificate? {
  let signed_data = @cms.parse_signed_data(token) catch { _ => return None }
  if signed_data.content_type != @oids.id_ct_tst_info {
    return None
  }
  if signed_data.signer_infos.length() == 0 {
    return None
  }
  let signer_info = signed_data.signer_infos[0]
  let certificate = match @cms.signer_certificate(signed_data, signer_info) {
    Some(value) => value
    None => return None
  }
  let content = match signed_data.econtent {
    Some(value) => value
    None => return None
  }
  let hash = match @crypto.Hash::from_oid(signer_info.digest_oid) {
    Some(value) => value
    None => return None
  }
  let digest = @crypto.digest(hash, content)
  if @cms.verify_signer(signer_info, certificate, digest) {
    Some(certificate)
  } else {
    None
  }
}

///|
/// Verify the token signature and build a chain from the TSA certificate to one
/// of `anchors`. The TSA certificate must carry the timeStamping EKU.
pub fn verify_token_chain(
  token : Bytes,
  anchors : Array[@x509.Certificate],
  at_time : Int64,
) -> @trust.Chain raise TsaError {
  let signer = match verify_token_signature(token) {
    Some(value) => value
    None =>
      raise TsaError::BadResponse("timestamp token signature does not verify")
  }
  if !signer.has_extended_key_usage(@oids.id_kp_time_stamping) {
    raise TsaError::BadResponse(
      "TSA certificate lacks the timeStamping extended key usage",
    )
  }
  let signed_data = @cms.parse_signed_data(token) catch {
    e => raise TsaError::Cms(e)
  }
  let intermediates : Array[@x509.Certificate] = []
  for der in signed_data.certificates {
    if @der.der_bytes_compare(der, signer.der) == 0 {
      continue
    }
    let parsed = @x509.parse_certificate(der) catch { _ => continue }
    intermediates.push(parsed)
  }
  @trust.build_chain(signer, intermediates, anchors, at_time) catch {
    e => raise TsaError::Trust(e.message())
  }
}

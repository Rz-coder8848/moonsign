///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise CmsError {
  reader.read_tlv() catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise CmsError {
  reader.read_sequence() catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn read_set(reader : @der.DerReader) -> @der.DerReader raise CmsError {
  reader.read_set() catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise CmsError {
  reader.read_oid() catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn read_int(reader : @der.DerReader) -> Int32 raise CmsError {
  reader.read_integer_int() catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn reader_at(
  bytes : Bytes,
  start : Int32,
  end : Int32,
) -> @der.DerReader raise CmsError {
  @der.DerReader::at(bytes, start, end) catch {
    e => raise CmsError::Der(e)
  }
}

///|
fn parse_algorithm(
  reader : @der.DerReader,
) -> AlgorithmIdentifier raise CmsError {
  let seq = read_seq(reader)
  let oid = read_oid(seq)
  let params = if seq.is_empty() { None } else { Some(read_tlv(seq).raw) }
  { oid, params_raw: params, }
}

///|
fn parse_attributes(content : Bytes) -> Array[Attribute] raise CmsError {
  let reader = reader_at(content, 0, content.length())
  let out : Array[Attribute] = []
  while !reader.is_empty() {
    let seq = read_seq(reader)
    let oid = read_oid(seq)
    let values_reader = read_set(seq)
    let values : Array[Bytes] = []
    while !values_reader.is_empty() {
      values.push(read_tlv(values_reader).raw)
    }
    out.push({ oid, values, })
  }
  out
}

///|
fn parse_signer_info(reader : @der.DerReader) -> SignerInfo raise CmsError {
  let seq = read_seq(reader)
  let version = read_int(seq)
  let issuer_and_serial = read_seq(seq)
  let issuer = read_tlv(issuer_and_serial)
  let serial = read_tlv(issuer_and_serial)
  if issuer.tag != @der.tag_sequence || serial.tag != @der.tag_integer {
    raise CmsError::Malformed("bad IssuerAndSerialNumber")
  }
  let digest = parse_algorithm(seq)
  let signed_attrs_tlv = read_tlv(seq)
  if signed_attrs_tlv.tag != 0xA0 {
    raise CmsError::Malformed("expected [0] IMPLICIT signed attributes")
  }
  let signed_attrs = parse_attributes(signed_attrs_tlv.content)
  let signature_algorithm = parse_algorithm(seq)
  let signature = read_tlv(seq)
  if signature.tag != @der.tag_octet_string {
    raise CmsError::Malformed("expected signature OCTET STRING")
  }
  let unsigned_attrs_raw = if seq.is_empty() {
    None
  } else {
    Some(read_tlv(seq).raw)
  }
  {
    version,
    issuer_raw: issuer.raw,
    serial_raw: serial.raw,
    digest_oid: digest.oid,
    signed_attrs_raw: signed_attrs_tlv.raw,
    signed_attrs,
    signature_oid: signature_algorithm.oid,
    signature: signature.content,
    unsigned_attrs_raw,
  }
}

///|
/// Parse a DER-encoded CMS ContentInfo containing SignedData.
pub fn parse_signed_data(der : Bytes) -> SignedData raise CmsError {
  let outer = @der.DerReader::new(der)
  let content_info = read_seq(outer)
  let content_type = read_oid(content_info)
  if content_type != @oids.id_signed_data {
    raise CmsError::NotSignedData
  }
  let explicit = read_tlv(content_info)
  if explicit.tag != 0xA0 {
    raise CmsError::Malformed("expected [0] EXPLICIT SignedData")
  }
  let signed_data_reader = reader_at(
    explicit.content,
    0,
    explicit.content.length(),
  )
  let signed_data = read_seq(signed_data_reader)
  let version = read_int(signed_data)
  let digest_algorithms = read_set(signed_data)
  // Parse and validate the digest algorithm set, but the per-signer value is
  // authoritative for verification.
  while !digest_algorithms.is_empty() {
    let _ = parse_algorithm(digest_algorithms)
  }
  let encap = read_seq(signed_data)
  let encap_content_type = read_oid(encap)
  let econtent = match encap.peek_tag() {
    Some(tag) =>
      if tag == 0xA0 {
        let wrapped = read_tlv(encap)
        let wrapper = reader_at(wrapped.content, 0, wrapped.content.length())
        let octets = read_tlv(wrapper)
        if octets.tag != @der.tag_octet_string {
          raise CmsError::Malformed("expected eContent OCTET STRING")
        }
        Some(octets.content)
      } else {
        None
      }
    None => None
  }
  let certificates : Array[Bytes] = []
  match signed_data.peek_tag() {
    Some(tag) =>
      if tag == 0xA0 {
        let certs = read_tlv(signed_data)
        let cert_reader = reader_at(certs.content, 0, certs.content.length())
        while !cert_reader.is_empty() {
          certificates.push(read_tlv(cert_reader).raw)
        }
      }
    None => ()
  }
  let signer_set = read_set(signed_data)
  let signer_infos : Array[SignerInfo] = []
  while !signer_set.is_empty() {
    signer_infos.push(parse_signer_info(signer_set))
  }
  {
    version,
    content_type: encap_content_type,
    econtent,
    certificates,
    signer_infos,
  }
}

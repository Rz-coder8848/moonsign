///|
fn attribute(oid : String, values : Array[Bytes]) -> Bytes {
  @der.der_sequence([@oids.encode(oid), @der.der_set(values)])
}

///|
/// Build the DER `SET OF Attribute` that is signed by the signer.
///
/// The returned bytes are tagged as a SET (0x31); `assemble_signed_data`
/// retags a copy as `[0] IMPLICIT` for embedding. The same bytes must be
/// passed to the signature function.
pub fn build_signed_attrs(
  content_type : String,
  message_digest : Bytes,
  signing_time : Int64?,
  signing_cert : @x509.Certificate,
  hash : @crypto.Hash,
) -> Bytes {
  let attrs : Array[Bytes] = []
  attrs.push(attribute(@oids.id_content_type, [@oids.encode(content_type)]))
  match signing_time {
    Some(unix) =>
      attrs.push(attribute(@oids.id_signing_time, [@der.der_time_auto(unix)]))
    None => ()
  }
  attrs.push(
    attribute(@oids.id_message_digest, [@der.der_octet_string(message_digest)]),
  )
  let cert_hash = @crypto.digest(hash, signing_cert.der)
  let ess_cert_id = @der.der_sequence([
    @der.der_sequence([@oids.encode(hash.oid()), @der.der_null()]),
    @der.der_octet_string(cert_hash),
  ])
  // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
  let certs = @der.der_sequence([ess_cert_id])
  let signing_certificate_v2 = @der.der_sequence([certs])
  attrs.push(
    attribute(@oids.id_signing_certificate_v2, [signing_certificate_v2]),
  )
  @der.der_set(attrs)
}

///|
fn is_rsa_signature(oid : String) -> Bool {
  oid == @oids.rsa_encryption ||
  oid == @oids.sha1_with_rsa ||
  oid == @oids.sha256_with_rsa ||
  oid == @oids.sha384_with_rsa ||
  oid == @oids.sha512_with_rsa
}

///|
/// Retag a DER SET (0x31) as `[0] IMPLICIT` (0xA0), preserving length and
/// content. Returns a copy.
pub fn signed_attrs_to_implicit(signed_attrs : Bytes) -> Bytes {
  let out = Array::make(signed_attrs.length(), b'\x00')
  for i in 0..<signed_attrs.length() {
    out[i] = signed_attrs[i]
  }
  if out.length() > 0 {
    out[0] = b'\xa0'
  }
  Bytes::from_array(out[:])
}

///|
/// Retag a `[0] IMPLICIT` signed attributes value as a DER SET (0x31).
///
/// CMS signs the SET OF encoding, not the implicit form that appears in the
/// file, so verification must perform this transformation.
pub fn signed_attrs_from_implicit(implicit : Bytes) -> Bytes {
  let out = Array::make(implicit.length(), b'\x00')
  for i in 0..<implicit.length() {
    out[i] = implicit[i]
  }
  if out.length() > 0 {
    out[0] = b'\x31'
  }
  Bytes::from_array(out[:])
}

///|
/// Assemble a detached CMS `SignedData` (ContentInfo) around an already
/// computed signature.
pub fn assemble_signed_data(
  signed_attrs : Bytes,
  signature : Bytes,
  hash : @crypto.Hash,
  signature_oid : String,
  signer : @x509.Certificate,
  extra_certs : Array[Bytes],
  content_type : String,
) -> Bytes {
  let digest_algorithm = @der.der_sequence([@oids.encode(hash.oid())])
  let signature_algorithm = if is_rsa_signature(signature_oid) {
    @der.der_sequence([@oids.encode(signature_oid), @der.der_null()])
  } else {
    @der.der_sequence([@oids.encode(signature_oid)])
  }
  let certificate_parts : Array[Bytes] = [signer.der]
  for cert in extra_certs {
    certificate_parts.push(cert)
  }
  let certificates = @der.der_context(
    0,
    true,
    @der.der_bytes_concat(certificate_parts),
  )
  let issuer_and_serial = @der.der_sequence([
    signer.issuer_raw,
    signer.serial_raw,
  ])
  let signer_info = @der.der_sequence([
    @der.der_integer_int(1),
    issuer_and_serial,
    digest_algorithm,
    signed_attrs_to_implicit(signed_attrs),
    signature_algorithm,
    @der.der_octet_string(signature),
  ])
  let signed_data = @der.der_sequence([
    @der.der_integer_int(1),
    @der.der_set([digest_algorithm]),
    @der.der_sequence([@oids.encode(content_type)]),
    certificates,
    @der.der_set([signer_info]),
  ])
  @der.der_sequence([
    @oids.encode(@oids.id_signed_data),
    @der.der_context_explicit(0, signed_data),
  ])
}

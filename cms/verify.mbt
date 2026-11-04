///|
fn attribute_value_octets(si : SignerInfo, oid : String) -> Bytes? {
  for attr in si.signed_attrs {
    if attr.oid == oid && attr.values.length() > 0 {
      let reader = @der.DerReader::new(attr.values[0])
      let tlv = reader.read_tlv() catch { _ => return None }
      if tlv.tag == @der.tag_octet_string {
        return Some(tlv.content)
      }
      return None
    }
  }
  None
}

///|
/// Whether the signature algorithm OID is one this build can verify.
pub fn signature_algorithm_supported(oid : String) -> Bool {
  oid == @oids.rsa_encryption ||
  oid == @oids.sha1_with_rsa ||
  oid == @oids.sha256_with_rsa ||
  oid == @oids.sha384_with_rsa ||
  oid == @oids.sha512_with_rsa ||
  oid == @oids.ecdsa_with_sha256 ||
  oid == @oids.ecdsa_with_sha384 ||
  oid == @oids.ecdsa_with_sha512
}

///|
/// Verify one signer: messageDigest attribute, then the signature over the
/// `SET OF` encoding of the signed attributes.
///
/// `content_digest` is the digest of the detached content (for PDFs, the hash
/// of the byte ranges).
pub fn verify_signer(
  si : SignerInfo,
  cert : @x509.Certificate,
  content_digest : Bytes,
) -> Bool {
  let hash = match @crypto.Hash::from_oid(si.digest_oid) {
    Some(h) => h
    None => return false
  }
  let declared = match attribute_value_octets(si, @oids.id_message_digest) {
    Some(value) => value
    None => return false
  }
  if @der.der_bytes_compare(declared, content_digest) != 0 {
    return false
  }
  let attrs = signed_attrs_from_implicit(si.signed_attrs_raw)
  if si.signature_oid == @oids.rsa_encryption ||
    si.signature_oid == @oids.sha1_with_rsa ||
    si.signature_oid == @oids.sha256_with_rsa ||
    si.signature_oid == @oids.sha384_with_rsa ||
    si.signature_oid == @oids.sha512_with_rsa {
    match cert.rsa_public_key() {
      Some((modulus, exponent)) =>
        @crypto.verify_rsa_pkcs1(hash, attrs, si.signature, modulus, exponent)
      None => false
    }
  } else if si.signature_oid == @oids.ecdsa_with_sha256 ||
    si.signature_oid == @oids.ecdsa_with_sha384 ||
    si.signature_oid == @oids.ecdsa_with_sha512 {
    match cert.ec_public_key() {
      Some(point) => @crypto.verify_ecdsa_p256(hash, attrs, si.signature, point)
      None => false
    }
  } else {
    false
  }
}

///|
fn try_parse_certificate(der : Bytes) -> @x509.Certificate? {
  Some(@x509.parse_certificate(der)) catch {
    _ => None
  }
}

///|
/// Find the signer certificate inside the CMS certificates set by matching
/// issuer and serial number.
pub fn signer_certificate(
  sd : SignedData,
  si : SignerInfo,
) -> @x509.Certificate? {
  for der in sd.certificates {
    let cert = match try_parse_certificate(der) {
      Some(c) => c
      None => continue
    }
    if @der.der_bytes_compare(cert.issuer_raw, si.issuer_raw) == 0 &&
      @der.der_bytes_compare(cert.serial_raw, si.serial_raw) == 0 {
      return Some(cert)
    }
  }
  None
}

///|
/// Verify the first signer of a parsed SignedData against a known certificate.
pub fn verify_signed_data(
  sd : SignedData,
  cert : @x509.Certificate,
  content_digest : Bytes,
) -> Bool {
  if sd.signer_infos.length() == 0 {
    return false
  }
  verify_signer(sd.signer_infos[0], cert, content_digest)
}

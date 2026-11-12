///|
/// Errors raised by the PAdES orchestration layer.
pub(all) suberror PadesError {
  Pdf(@pdf.PdfSignError)
  Cms(@cms.CmsError)
  Crypto(@crypto.CryptoError)
  X509(@x509.X509Error)
  Tsa(String)
  NoSignature
  UnsupportedSubfilter(String)
  UnsupportedDigest(String)
  ByteRangeMismatch
}

///|
/// Signing key material. Keys are raw big-endian scalars/moduli, as parsed by
/// the caller (for example from PKCS#8).
pub(all) enum SigningKey {
  /// RSA: modulus, private exponent.
  Rsa(Bytes, Bytes)
  /// ECDSA P-256: 32-byte private scalar.
  EcdsaP256(Bytes)
}

///|
/// Options for `sign_pdf`.
pub(all) struct SignOptions {
  field_name : String
  contents_chars : Int32
  signing_time : Int64?
  reason : String?
  location : String?
  contact : String?
  appearance : @pdf.SignatureAppearance?
  hash : @crypto.Hash
}

///|
/// Default options: field `Signature1`, 8192 bytes of CMS capacity, SHA-256.
pub fn default_sign_options() -> SignOptions {
  {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
}

///|
fn signature_oid_for_rsa(hash : @crypto.Hash) -> String raise PadesError {
  match hash {
    Sha1 => @oids.sha1_with_rsa
    Sha256 => @oids.sha256_with_rsa
    Sha384 => @oids.sha384_with_rsa
    Sha512 => @oids.sha512_with_rsa
    Sm3 => raise PadesError::UnsupportedDigest("SM3 with RSA is not supported")
  }
}

///|
fn signature_oid_for_ecdsa(hash : @crypto.Hash) -> String raise PadesError {
  match hash {
    Sha256 => @oids.ecdsa_with_sha256
    Sha384 => @oids.ecdsa_with_sha384
    Sha512 => @oids.ecdsa_with_sha512
    _ => raise PadesError::UnsupportedDigest("ECDSA P-256 uses SHA-256")
  }
}

///|
/// Sign a PDF with PAdES B-B (detached CMS, `ETSI.CAdES.detached`).
pub fn sign_pdf(
  pdf_bytes : Bytes,
  key : SigningKey,
  certificate : @x509.Certificate,
  extra_certs : Array[Bytes],
  options : SignOptions,
) -> Bytes raise PadesError {
  let prepared = @pdf.prepare(
    pdf_bytes,
    options.field_name,
    options.contents_chars,
    reason?=options.reason,
    location?=options.location,
    contact?=options.contact,
    signing_time?=options.signing_time,
    appearance?=options.appearance,
  ) catch {
    e => raise PadesError::Pdf(e)
  }
  let (sealed_pdf, slot) = @pdf.seal_layout(prepared, options.contents_chars) catch {
    e => raise PadesError::Pdf(e)
  }
  let parts = @pdf.signed_ranges(sealed_pdf, slot)
  let digest = @crypto.digest_parts(options.hash, parts)
  let signed_attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    options.signing_time,
    certificate,
    options.hash,
  )
  let (signature, signature_oid) = match key {
    Rsa(modulus, private_exponent) => {
      let value = @crypto.sign_rsa_pkcs1(
        options.hash,
        signed_attrs,
        modulus,
        private_exponent,
      ) catch {
        e => raise PadesError::Crypto(e)
      }
      (value, signature_oid_for_rsa(options.hash))
    }
    EcdsaP256(private_key) => {
      let value = @crypto.sign_ecdsa_p256(
        options.hash,
        signed_attrs,
        private_key,
      ) catch {
        e => raise PadesError::Crypto(e)
      }
      (value, signature_oid_for_ecdsa(options.hash))
    }
  }
  let cms_bytes = @cms.assemble_signed_data(
    signed_attrs,
    signature,
    options.hash,
    signature_oid,
    certificate,
    extra_certs,
    @oids.id_data,
  )
  @pdf.embed(sealed_pdf, slot, cms_bytes) catch {
    e => raise PadesError::Pdf(e)
  }
}

///|
/// Verify the first signature of a PDF against a known certificate.
///
/// This checks the byte ranges, the CMS message digest and the signature. It
/// does not build a certificate chain; callers that need trust decisions must
/// check the certificate themselves.
pub fn verify_pdf(
  pdf_bytes : Bytes,
  certificate : @x509.Certificate,
) -> Bool raise PadesError {
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise PadesError::NoSignature
  }
  let signature = signatures[0]
  let parts = match @pdf.bytes_for_signature(pdf_bytes, signature) {
    Some(value) => value
    None => raise PadesError::ByteRangeMismatch
  }
  let signed_data = @cms.parse_signed_data(signature.contents) catch {
    e => raise PadesError::Cms(e)
  }
  if signed_data.signer_infos.length() == 0 {
    raise PadesError::NoSignature
  }
  let signer = signed_data.signer_infos[0]
  let hash = match @crypto.Hash::from_oid(signer.digest_oid) {
    Some(value) => value
    None => raise PadesError::UnsupportedDigest(signer.digest_oid)
  }
  let digest = @crypto.digest_parts(hash, parts)
  @cms.verify_signer(signer, certificate, digest)
}

///|
/// Human-readable description of a PAdES error.
pub fn PadesError::message(self : PadesError) -> String {
  match self {
    Pdf(detail) => "PDF error: \{detail.message()}"
    Cms(detail) => "CMS error: \{detail.message()}"
    Crypto(detail) => "crypto error: \{detail.message()}"
    X509(detail) => "X.509 error: \{detail.message()}"
    Tsa(detail) => "timestamp error: \{detail}"
    NoSignature => "no signature found"
    UnsupportedSubfilter(value) => "unsupported subfilter: \{value}"
    UnsupportedDigest(value) => "unsupported digest: \{value}"
    ByteRangeMismatch => "signature ByteRange is malformed"
  }
}

///|
/// Outcome of verifying a PDF signature together with certificate trust.
pub(all) struct VerifyOutcome {
  /// The CMS signature and the covered bytes are intact.
  signature_valid : Bool
  /// Certificate that produced the signature, when it could be located.
  signer : @x509.Certificate?
  /// Verified path to a trust anchor, when anchors were supplied.
  chain : @trust.Chain?
  /// Why the chain could not be built (only when anchors were supplied).
  trust_error : String?
}

///|
/// Verify a PDF signature and, when `anchors` is non-empty, build a chain from
/// the signer certificate to one of those anchors at `at_time`.
pub fn verify_pdf_with_anchors(
  pdf_bytes : Bytes,
  anchors : Array[@x509.Certificate],
  at_time : Int64,
) -> VerifyOutcome raise PadesError {
  verify_pdf_with_anchors_and_crls(pdf_bytes, anchors, [], at_time)
}

///|
/// Same as `verify_pdf_with_anchors`, but also checks revocation against
/// `crls` while building the certificate path.
pub fn verify_pdf_with_anchors_and_crls(
  pdf_bytes : Bytes,
  anchors : Array[@x509.Certificate],
  crls : Array[@x509.Crl],
  at_time : Int64,
) -> VerifyOutcome raise PadesError {
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise PadesError::NoSignature
  }
  let signature = signatures[0]
  let parts = match @pdf.bytes_for_signature(pdf_bytes, signature) {
    Some(value) => value
    None => raise PadesError::ByteRangeMismatch
  }
  let signed_data = @cms.parse_signed_data(signature.contents) catch {
    e => raise PadesError::Cms(e)
  }
  if signed_data.signer_infos.length() == 0 {
    raise PadesError::NoSignature
  }
  let signer_info = signed_data.signer_infos[0]
  let signer = match @cms.signer_certificate(signed_data, signer_info) {
    Some(value) => value
    None => raise PadesError::NoSignature
  }
  let hash = match @crypto.Hash::from_oid(signer_info.digest_oid) {
    Some(value) => value
    None => raise PadesError::UnsupportedDigest(signer_info.digest_oid)
  }
  let digest = @crypto.digest_parts(hash, parts)
  let signature_valid = @cms.verify_signer(signer_info, signer, digest)
  let mut chain : @trust.Chain? = None
  let mut trust_error : String? = None
  if anchors.length() > 0 {
    let intermediates : Array[@x509.Certificate] = []
    for der in signed_data.certificates {
      if @der.der_bytes_compare(der, signer.der) == 0 {
        continue
      }
      let parsed = @x509.parse_certificate(der) catch { _ => continue }
      intermediates.push(parsed)
    }
    let built : Result[@trust.Chain, String] = Ok(
      @trust.build_chain_with_crls(
        signer, intermediates, anchors, crls, at_time,
      ),
    ) catch {
      e => Err(e.message())
    }
    match built {
      Ok(value) => chain = Some(value)
      Err(message) => trust_error = Some(message)
    }
  }
  { signature_valid, signer: Some(signer), chain, trust_error, }
}

///|
/// Sign a PDF and attach an RFC 3161 timestamp (PAdES B-T).
///
/// `transport` receives a DER TimeStampReq and must return a DER TimeStampResp
/// (for example by POSTing it to a TSA with `application/timestamp-query`).
/// The timestamp token is checked against the signature before embedding.
pub fn sign_pdf_with_timestamp(
  pdf_bytes : Bytes,
  key : SigningKey,
  certificate : @x509.Certificate,
  extra_certs : Array[Bytes],
  options : SignOptions,
  transport : (Bytes) -> Result[Bytes, String],
) -> Bytes raise PadesError {
  let prepared = @pdf.prepare(
    pdf_bytes,
    options.field_name,
    options.contents_chars,
    reason?=options.reason,
    location?=options.location,
    contact?=options.contact,
    signing_time?=options.signing_time,
    appearance?=options.appearance,
  ) catch {
    e => raise PadesError::Pdf(e)
  }
  let (sealed_pdf, slot) = @pdf.seal_layout(prepared, options.contents_chars) catch {
    e => raise PadesError::Pdf(e)
  }
  let parts = @pdf.signed_ranges(sealed_pdf, slot)
  let digest = @crypto.digest_parts(options.hash, parts)
  let signed_attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    options.signing_time,
    certificate,
    options.hash,
  )
  let (signature, signature_oid) = match key {
    Rsa(modulus, private_exponent) => {
      let value = @crypto.sign_rsa_pkcs1(
        options.hash,
        signed_attrs,
        modulus,
        private_exponent,
      ) catch {
        e => raise PadesError::Crypto(e)
      }
      (value, signature_oid_for_rsa(options.hash))
    }
    EcdsaP256(private_key) => {
      let value = @crypto.sign_ecdsa_p256(
        options.hash,
        signed_attrs,
        private_key,
      ) catch {
        e => raise PadesError::Crypto(e)
      }
      (value, signature_oid_for_ecdsa(options.hash))
    }
  }
  let request = @tsa.build_request(signature, options.hash, true)
  let response = match transport(request) {
    Ok(value) => value
    Err(message) => raise PadesError::Tsa(message)
  }
  let parsed = @tsa.parse_response(response) catch {
    e => raise PadesError::Tsa(e.message())
  }
  if parsed.status != 0 && parsed.status != 1 {
    raise PadesError::Tsa(
      "timestamp authority status " + parsed.status.to_string(),
    )
  }
  let token = match parsed.token {
    Some(value) => value
    None => raise PadesError::Tsa("timestamp response contains no token")
  }
  if !@tsa.verify_token(token, signature, options.hash) {
    raise PadesError::Tsa("timestamp token does not match the signature")
  }
  let cms_bytes = @cms.assemble_signed_data(
    signed_attrs,
    signature,
    options.hash,
    signature_oid,
    certificate,
    extra_certs,
    @oids.id_data,
    timestamp_token=token,
  )
  @pdf.embed(sealed_pdf, slot, cms_bytes) catch {
    e => raise PadesError::Pdf(e)
  }
}

///|
/// Result of checking the timestamp token attached to a signature.
pub(all) struct TimestampOutcome {
  present : Bool
  valid : Bool
  chain : @trust.Chain?
  error : String?
}

///|
/// Check the RFC 3161 timestamp of signature `index`.
///
/// `tsa_anchors` may be empty: the token signature and its match with the
/// signature value are still checked, but TSA trust is not.
pub fn verify_timestamp_at(
  pdf_bytes : Bytes,
  index : Int32,
  tsa_anchors : Array[@x509.Certificate],
  at_time : Int64,
) -> TimestampOutcome raise PadesError {
  let signatures = @pdf.find_signatures(pdf_bytes)
  if index < 0 || index >= signatures.length() {
    raise PadesError::NoSignature
  }
  let signature = signatures[index]
  let signed_data = @cms.parse_signed_data(signature.contents) catch {
    e => raise PadesError::Cms(e)
  }
  if signed_data.signer_infos.length() == 0 {
    raise PadesError::NoSignature
  }
  let signer_info = signed_data.signer_infos[0]
  let attributes = @cms.unsigned_attributes(signer_info) catch {
    e => raise PadesError::Cms(e)
  }
  let mut token : Bytes? = None
  for attribute in attributes {
    if attribute.oid == @oids.id_aa_signature_time_stamp &&
      attribute.values.length() > 0 {
      token = Some(attribute.values[0])
    }
  }
  let token_value = match token {
    Some(value) => value
    None => return { present: false, valid: false, chain: None, error: None, }
  }
  let hash = match @crypto.Hash::from_oid(signer_info.digest_oid) {
    Some(value) => value
    None => raise PadesError::UnsupportedDigest(signer_info.digest_oid)
  }
  let valid = @tsa.verify_token(token_value, signer_info.signature, hash)
  if !valid {
    return {
      present: true,
      valid: false,
      chain: None,
      error: Some("timestamp token does not match the signature"),
    }
  }
  if tsa_anchors.length() == 0 {
    return { present: true, valid: true, chain: None, error: None, }
  }
  let built : Result[@trust.Chain, String] = Ok(
    @tsa.verify_token_chain(token_value, tsa_anchors, at_time),
  ) catch {
    e => Err(e.message())
  }
  match built {
    Ok(chain) =>
      { present: true, valid: true, chain: Some(chain), error: None, }
    Err(message) =>
      { present: true, valid: true, chain: None, error: Some(message), }
  }
}

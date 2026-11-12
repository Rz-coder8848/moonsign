///|
fn base_pdf() -> Bytes {
  let document = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => abort("failed to create the minimal PDF")
  }
  @pdflite.pdf_write_document(document) catch {
    _ => abort("failed to serialize the minimal PDF")
  }
}

///|
fn rsa_certificate() -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex)) catch {
    _ => abort("failed to parse the RSA fixture certificate")
  }
}

///|
fn ec_certificate() -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(@fixtures.ec_cert_der_hex)) catch {
    _ => abort("failed to parse the EC fixture certificate")
  }
}

///|
fn rsa_signing_key() -> @pades.SigningKey {
  let cert = rsa_certificate()
  let (modulus, _) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => abort("expected an RSA public key")
  }
  @pades.SigningKey::Rsa(modulus, @fixtures.bytes_of_hex(@fixtures.rsa_d_hex))
}

///|
test "sign and verify RSA PDF" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1793793600L),
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  let outcome = try {
    if @pades.verify_pdf(signed, cert) {
      "valid"
    } else {
      "invalid"
    }
  } catch {
    e => "error: " + e.message()
  }
  inspect(outcome, content="valid")
  let signatures = @pdf.signatures(signed) catch {
    _ => abort("failed to extract signatures")
  }
  inspect(signatures.length(), content="1")
  inspect(signatures[0].field_name, content="Signature1")
  inspect(signatures[0].subfilter, content="ETSI.CAdES.detached")
  inspect(signatures[0].byte_range.length(), content="4")
  inspect(signatures[0].contents.length() > 100, content="true")
}

///|
test "sign and verify ECDSA PDF" {
  let cert = ec_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature2",
    contents_chars: 16384,
    signing_time: None,
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(
    base_pdf(),
    @pades.SigningKey::EcdsaP256(@fixtures.bytes_of_hex(@fixtures.ec_priv_hex)),
    cert,
    [],
    options,
  ) catch {
    _ => abort("ECDSA signing failed")
  }
  let outcome = try {
    if @pades.verify_pdf(signed, cert) {
      "valid"
    } else {
      "invalid"
    }
  } catch {
    e => "error: " + e.message()
  }
  inspect(outcome, content="valid")
}

///|
test "tampering invalidates the signature" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  let tampered = Array::make(signed.length(), b'\x00')
  for i in 0..<signed.length() {
    tampered[i] = signed[i]
  }
  tampered[10] = (tampered[10].to_int() ^ 0x01).to_byte()
  inspect(
    @pades.verify_pdf(Bytes::from_array(tampered[:]), cert) catch {
      _ => false
    },
    content="false",
  )
}

///|
test "wrong certificate fails verification" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  inspect(
    @pades.verify_pdf(signed, ec_certificate()) catch {
      _ => false
    },
    content="false",
  )
}

///|
test "verify with a trusted anchor" {
  let leaf = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.chain_leaf_der_hex),
  ) catch {
    _ => abort("leaf")
  }
  let intermediate = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.chain_intermediate_der_hex),
  ) catch {
    _ => abort("intermediate")
  }
  let root = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.chain_root_der_hex),
  ) catch {
    _ => abort("root")
  }
  let key = @pem.parse_private_key(
    @fixtures.bytes_of_hex(@fixtures.chain_leaf_key_der_hex),
  ) catch {
    _ => abort("leaf key")
  }
  let (modulus, private_exponent) = match key {
    @pem.PrivateKey::Rsa(n, d) => (n, d)
    _ => abort("expected RSA leaf key")
  }
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(
    base_pdf(),
    @pades.SigningKey::Rsa(modulus, private_exponent),
    leaf,
    [intermediate.der, root.der],
    options,
  ) catch {
    e => abort(e.message())
  }
  let outcome = @pades.verify_pdf_with_anchors(signed, [root], 1794500000L) catch {
    e => abort(e.message())
  }
  inspect(outcome.signature_valid, content="true")
  match outcome.chain {
    Some(chain) => {
      inspect(chain.trusted, content="true")
      inspect(chain.certificates.length(), content="3")
    }
    None => fail("expected a verified chain")
  }
  let wrong = @pades.verify_pdf_with_anchors(
    signed,
    [rsa_certificate()],
    1794500000L,
  ) catch {
    e => abort(e.message())
  }
  inspect(wrong.signature_valid, content="true")
  match wrong.trust_error {
    Some(_) => ()
    None => fail("expected a trust error with a wrong anchor")
  }
}

///|
fn fake_tsa_token(request : Bytes) -> Result[Bytes, String] {
  let imprint = @tsa.request_imprint(request) catch {
    e => return Err(e.message())
  }
  let (oid, hashed) = imprint
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.tsa_cert_der_hex),
  ) catch {
    _ => return Err("tsa cert")
  }
  let key = @pem.parse_private_key(
    @fixtures.bytes_of_hex(@fixtures.tsa_key_der_hex),
  ) catch {
    _ => return Err("tsa key")
  }
  let private_exponent = match key {
    @pem.PrivateKey::Rsa(_, d) => d
    _ => return Err("expected an RSA TSA key")
  }
  let tst_info = @der.der_sequence([
    @der.der_integer_int(1),
    @oids.encode("1.2.3.4.1"),
    @der.der_sequence([
      @der.der_sequence([@oids.encode(oid)]),
      @der.der_octet_string(hashed),
    ]),
    @der.der_integer_int(7),
    @der.der_generalized_time(1794500000L),
  ])
  let content_digest = @crypto.digest(@crypto.Hash::Sha256, tst_info)
  let attrs = @cms.build_signed_attrs(
    @oids.id_ct_tst_info,
    content_digest,
    Some(1794500000L),
    cert,
    @crypto.Hash::Sha256,
  )
  let (modulus, _) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => return Err("tsa public key")
  }
  let signature = @crypto.sign_rsa_pkcs1(
    @crypto.Hash::Sha256,
    attrs,
    modulus,
    private_exponent,
  ) catch {
    e => return Err(e.message())
  }
  let token = @cms.assemble_signed_data(
    attrs,
    signature,
    @crypto.Hash::Sha256,
    @oids.sha256_with_rsa,
    cert,
    [],
    @oids.id_ct_tst_info,
    econtent=tst_info,
  )
  Ok(@tsa.wrap_response(token))
}

///|
test "sign with timestamp (B-T)" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1794500000L),
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf_with_timestamp(
    base_pdf(),
    rsa_signing_key(),
    cert,
    [],
    options,
    fake_tsa_token,
  ) catch {
    e => abort(e.message())
  }
  inspect(@pades.verify_pdf(signed, cert) catch { _ => false }, content="true")
  let signatures = @pdf.signatures(signed) catch { _ => abort("signatures") }
  let signed_data = @cms.parse_signed_data(signatures[0].contents) catch {
    _ => abort("cms")
  }
  let signer = signed_data.signer_infos[0]
  let attrs = @cms.unsigned_attributes(signer) catch { _ => abort("unsigned") }
  inspect(attrs.length(), content="1")
  inspect(attrs[0].oid, content=@oids.id_aa_signature_time_stamp)
  inspect(
    @tsa.verify_token(
      attrs[0].values[0],
      signer.signature,
      @crypto.Hash::Sha256,
    ),
    content="true",
  )
  match @cms.signing_time(signer) {
    Some(value) => inspect(value.to_string(), content="1794500000")
    None => fail("missing signing time")
  }
  let tsa_cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.tsa_cert_der_hex),
  ) catch {
    _ => abort("tsa cert")
  }
  let timestamp = @pades.verify_timestamp_at(signed, 0, [tsa_cert], 1794500000L) catch {
    e => abort(e.message())
  }
  inspect(timestamp.present, content="true")
  inspect(timestamp.valid, content="true")
  match timestamp.chain {
    Some(chain) => inspect(chain.trusted, content="true")
    None => fail("expected a TSA chain")
  }
}

///|
test "sign with a visible appearance" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1794500000L),
    reason: None,
    location: None,
    contact: None,
    appearance: Some({
      x1: 36,
      y1: 36,
      x2: 300,
      y2: 120,
      lines: ["Digitally signed", "2026-11-10"],
    }),
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    e => abort(e.message())
  }
  inspect(@pades.verify_pdf(signed, cert) catch { _ => false }, content="true")
}

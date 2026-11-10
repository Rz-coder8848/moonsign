///|
fn test_signature() -> Bytes {
  let out = Array::make(32, b'\x01')
  Bytes::from_array(out[:])
}

///|
test "timestamp request round trip" {
  let signature = test_signature()
  let request = @tsa.build_request(signature, @crypto.Hash::Sha256, true)
  inspect(request[0].to_int(), content="48")
  let (oid, hashed) = @tsa.request_imprint(request) catch {
    e => fail(e.message())
  }
  inspect(oid, content=@oids.sha256)
  inspect(
    @fixtures.hex_of_bytes(hashed),
    content=@fixtures.hex_of_bytes(
      @crypto.digest(@crypto.Hash::Sha256, signature),
    ),
  )
}

///|
fn fake_token(signature : Bytes) -> Bytes {
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.tsa_cert_der_hex),
  ) catch {
    _ => abort("tsa cert")
  }
  let key = @pem.parse_private_key(
    @fixtures.bytes_of_hex(@fixtures.tsa_key_der_hex),
  ) catch {
    _ => abort("tsa key")
  }
  let private_exponent = match key {
    @pem.PrivateKey::Rsa(_, d) => d
    _ => abort("expected an RSA TSA key")
  }
  let digest = @crypto.digest(@crypto.Hash::Sha256, signature)
  let tst_info = @der.der_sequence([
    @der.der_integer_int(1),
    @oids.encode("1.2.3.4.1"),
    @der.der_sequence([
      @der.der_sequence([@oids.encode(@oids.sha256)]),
      @der.der_octet_string(digest),
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
    None => abort("rsa key")
  }
  let signature_value = @crypto.sign_rsa_pkcs1(
    @crypto.Hash::Sha256,
    attrs,
    modulus,
    private_exponent,
  ) catch {
    _ => abort("tsa sign")
  }
  @cms.assemble_signed_data(
    attrs,
    signature_value,
    @crypto.Hash::Sha256,
    @oids.sha256_with_rsa,
    cert,
    [],
    @oids.id_ct_tst_info,
    econtent=tst_info,
  )
}

///|
test "timestamp response parsing and imprint" {
  let signature = test_signature()
  let token = fake_token(signature)
  let response = @tsa.wrap_response(token)
  let parsed = @tsa.parse_response(response) catch { e => fail(e.message()) }
  inspect(parsed.status, content="0")
  let extracted = match parsed.token {
    Some(value) => value
    None => fail("expected a token")
  }
  inspect(
    @tsa.verify_token(extracted, signature, @crypto.Hash::Sha256),
    content="true",
  )
  let tampered = Array::make(signature.length(), b'\x00')
  for i in 0..<signature.length() {
    tampered[i] = signature[i]
  }
  tampered[0] = b'\x02'
  inspect(
    @tsa.verify_token(
      extracted,
      Bytes::from_array(tampered[:]),
      @crypto.Hash::Sha256,
    ),
    content="false",
  )
}

///|
test "timestamp token signature and chain" {
  let signature = test_signature()
  let token = fake_token(signature)
  let signer = match @tsa.verify_token_signature(token) {
    Some(value) => value
    None => fail("timestamp token signature does not verify")
  }
  inspect(
    signer.has_extended_key_usage(@oids.id_kp_time_stamping),
    content="true",
  )
  let chain = @tsa.verify_token_chain(token, [signer], 1794500000L) catch {
    e => fail(e.message())
  }
  inspect(chain.trusted, content="true")
  let other = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => abort("other cert")
  }
  let failed = try {
    let _ = @tsa.verify_token_chain(token, [other], 1794500000L)
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

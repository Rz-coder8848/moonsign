///|
fn test_message() -> Bytes {
  @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
}

///|
test "signed attributes carry the required fields" {
  let message = test_message()
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  let attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    Some(1793793600L),
    cert,
    @crypto.Hash::Sha256,
  )
  inspect(attrs[0].to_int(), content="49")
  let reader = @der.DerReader::new(attrs)
  let set = reader.read_set() catch {
    _ => fail("signed attributes are not a SET")
  }
  let count = set.read_all() catch {
    _ => fail("failed to parse signed attributes")
  }
  inspect(count.length(), content="4")
}

///|
test "build and verify RSA CMS" {
  let message = test_message()
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  let (modulus, _exponent) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => fail("expected an RSA public key")
  }
  let attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    Some(1793793600L),
    cert,
    @crypto.Hash::Sha256,
  )
  let signature = @crypto.sign_rsa_pkcs1(
    @crypto.Hash::Sha256,
    attrs,
    modulus,
    @fixtures.bytes_of_hex(@fixtures.rsa_d_hex),
  ) catch {
    _ => fail("RSA signing failed")
  }
  let cms_bytes = @cms.assemble_signed_data(
    attrs,
    signature,
    @crypto.Hash::Sha256,
    @oids.sha256_with_rsa,
    cert,
    [],
    @oids.id_data,
  )
  let sd = @cms.parse_signed_data(cms_bytes) catch {
    _ => fail("failed to parse our own CMS")
  }
  inspect(sd.signer_infos.length(), content="1")
  inspect(sd.certificates.length(), content="1")
  inspect(@cms.verify_signed_data(sd, cert, digest), content="true")
}

///|
test "verify OpenSSL detached CMS" {
  let message = test_message()
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  let cms_bytes = @fixtures.bytes_of_hex(@fixtures.openssl_cms_detached_hex)
  let sd = @cms.parse_signed_data(cms_bytes) catch {
    _ => fail("failed to parse the OpenSSL CMS fixture")
  }
  inspect(sd.content_type, content="1.2.840.113549.1.7.1")
  inspect(sd.signer_infos.length(), content="1")
  inspect(@cms.verify_signed_data(sd, cert, digest), content="true")
}

///|
test "reject tampered digest and signature" {
  let message = test_message()
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  let (modulus, _exponent) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => fail("expected an RSA public key")
  }
  let attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    None,
    cert,
    @crypto.Hash::Sha256,
  )
  let signature = @crypto.sign_rsa_pkcs1(
    @crypto.Hash::Sha256,
    attrs,
    modulus,
    @fixtures.bytes_of_hex(@fixtures.rsa_d_hex),
  ) catch {
    _ => fail("RSA signing failed")
  }
  let cms_bytes = @cms.assemble_signed_data(
    attrs,
    signature,
    @crypto.Hash::Sha256,
    @oids.sha256_with_rsa,
    cert,
    [],
    @oids.id_data,
  )
  let sd = @cms.parse_signed_data(cms_bytes) catch {
    _ => fail("failed to parse our own CMS")
  }
  let wrong_digest = @fixtures.bytes_of_hex("00")
  inspect(@cms.verify_signed_data(sd, cert, wrong_digest), content="false")
  let tampered = Array::make(signature.length(), b'\x00')
  for i in 0..<signature.length() {
    tampered[i] = signature[i]
  }
  tampered[0] = (tampered[0].to_int() ^ 0x01).to_byte()
  let si = sd.signer_infos[0]
  let tampered_si : @cms.SignerInfo = {
    version: si.version,
    issuer_raw: si.issuer_raw,
    serial_raw: si.serial_raw,
    digest_oid: si.digest_oid,
    signed_attrs_raw: si.signed_attrs_raw,
    signed_attrs: si.signed_attrs,
    signature_oid: si.signature_oid,
    signature: Bytes::from_array(tampered[:]),
    unsigned_attrs_raw: si.unsigned_attrs_raw,
  }
  inspect(@cms.verify_signer(tampered_si, cert, digest), content="false")
}

///|
test "build and verify ECDSA CMS" {
  let message = test_message()
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.ec_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the EC fixture certificate")
  }
  let attrs = @cms.build_signed_attrs(
    @oids.id_data,
    digest,
    Some(1793793600L),
    cert,
    @crypto.Hash::Sha256,
  )
  let signature = @crypto.sign_ecdsa_p256(
    @crypto.Hash::Sha256,
    attrs,
    @fixtures.bytes_of_hex(@fixtures.ec_priv_hex),
  ) catch {
    _ => fail("ECDSA signing failed")
  }
  let cms_bytes = @cms.assemble_signed_data(
    attrs,
    signature,
    @crypto.Hash::Sha256,
    @oids.ecdsa_with_sha256,
    cert,
    [],
    @oids.id_data,
  )
  let sd = @cms.parse_signed_data(cms_bytes) catch {
    _ => fail("failed to parse our own ECDSA CMS")
  }
  inspect(@cms.verify_signed_data(sd, cert, digest), content="true")
}

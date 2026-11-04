///|
test "parse rsa certificate" {
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  inspect(cert.spki_algorithm_oid, content="1.2.840.113549.1.1.1")
  inspect(cert.signature_algorithm_oid, content="1.2.840.113549.1.1.11")
  match cert.rsa_public_key() {
    Some((modulus, exponent)) => {
      inspect(@fixtures.hex_of_bytes(modulus), content=@fixtures.rsa_n_hex)
      inspect(@fixtures.hex_of_bytes(exponent), content=@fixtures.rsa_e_hex)
    }
    None => fail("expected an RSA public key")
  }
  inspect(cert.is_valid_at(1800000000L), content="true")
  inspect(cert.is_valid_at(0L), content="false")
}

///|
test "parse ec certificate" {
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.ec_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the EC fixture certificate")
  }
  inspect(cert.spki_algorithm_oid, content="1.2.840.10045.2.1")
  match cert.curve_oid() {
    Some(oid) => inspect(oid, content="1.2.840.10045.3.1.7")
    None => fail("expected a named curve")
  }
  match cert.ec_public_key() {
    Some(point) => {
      inspect(point.length(), content="65")
      inspect(point[0].to_int(), content="4")
    }
    None => fail("expected an EC public key")
  }
}

///|
test "reject malformed certificate" {
  let failed = try {
    let _ = @x509.parse_certificate(@fixtures.bytes_of_hex("3003020101"))
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

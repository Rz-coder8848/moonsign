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

///|
fn chain_cert(hex : String) -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(hex)) catch {
    _ => abort("failed to parse chain certificate")
  }
}

///|
test "parse certificate extensions" {
  let root = chain_cert(@fixtures.chain_root_der_hex)
  inspect(root.is_ca, content="true")
  inspect(root.key_cert_sign, content="true")
  let intermediate = chain_cert(@fixtures.chain_intermediate_der_hex)
  inspect(intermediate.is_ca, content="true")
  inspect(intermediate.key_cert_sign, content="true")
  match intermediate.path_len {
    Some(limit) => inspect(limit, content="0")
    None => fail("expected a path length constraint")
  }
  let leaf = chain_cert(@fixtures.chain_leaf_der_hex)
  inspect(leaf.is_ca, content="false")
  inspect(leaf.key_cert_sign, content="false")
  match leaf.authority_key_id {
    Some(_) => ()
    None => fail("expected an authority key identifier")
  }
}

///|
test "verify certificate signatures" {
  let root = chain_cert(@fixtures.chain_root_der_hex)
  let intermediate = chain_cert(@fixtures.chain_intermediate_der_hex)
  let leaf = chain_cert(@fixtures.chain_leaf_der_hex)
  inspect(
    @x509.verify_certificate_signature(leaf, intermediate),
    content="true",
  )
  inspect(
    @x509.verify_certificate_signature(intermediate, root),
    content="true",
  )
  inspect(@x509.verify_certificate_signature(root, root), content="true")
  inspect(@x509.verify_certificate_signature(leaf, root), content="false")
}

///|
fn ocsp_cert(hex : String) -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(hex)) catch {
    _ => abort("failed to parse certificate")
  }
}

///|
test "parse a good OCSP response" {
  let leaf = ocsp_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = ocsp_cert(@fixtures.chain_intermediate_der_hex)
  let response = @ocsp.parse_response(
    @fixtures.bytes_of_hex(@fixtures.ocsp_good_der_hex),
  ) catch {
    e => fail(e.message())
  }
  inspect(response.status, content="0")
  inspect(response.responses.length(), content="1")
  match @ocsp.check(response, leaf, intermediate, 1794500000L) {
    @ocsp.CertStatus::Good => ()
    _ => fail("expected a good status")
  }
}

///|
test "parse a revoked OCSP response" {
  let leaf = ocsp_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = ocsp_cert(@fixtures.chain_intermediate_der_hex)
  let response = @ocsp.parse_response(
    @fixtures.bytes_of_hex(@fixtures.ocsp_revoked_der_hex),
  ) catch {
    e => fail(e.message())
  }
  match @ocsp.check(response, leaf, intermediate, 1794500000L) {
    @ocsp.CertStatus::Revoked(_) => ()
    _ => fail("expected a revoked status")
  }
}

///|
test "OCSP response for another certificate is rejected" {
  let other = ocsp_cert(@fixtures.rsa_cert_der_hex)
  let intermediate = ocsp_cert(@fixtures.chain_intermediate_der_hex)
  let response = @ocsp.parse_response(
    @fixtures.bytes_of_hex(@fixtures.ocsp_good_der_hex),
  ) catch {
    e => fail(e.message())
  }
  let failed = try {
    let _ = @ocsp.check(response, other, intermediate, 1794500000L)
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
fn trust_cert(hex : String) -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(hex)) catch {
    _ => abort("failed to parse chain certificate")
  }
}

///|
test "build a valid chain to the root" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let root = trust_cert(@fixtures.chain_root_der_hex)
  let chain = @trust.build_chain(leaf, [intermediate], [root], 1794500000L) catch {
    e => fail(e.message())
  }
  inspect(chain.trusted, content="true")
  inspect(chain.certificates.length(), content="3")
}

///|
test "intermediate can be a trust anchor" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let chain = @trust.build_chain(leaf, [], [intermediate], 1794500000L) catch {
    e => fail(e.message())
  }
  inspect(chain.trusted, content="true")
  inspect(chain.certificates.length(), content="2")
}

///|
test "unknown anchor produces no chain" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let other = trust_cert(@fixtures.rsa_cert_der_hex)
  let failed = try {
    let _ = @trust.build_chain(leaf, [intermediate], [other], 1794500000L)
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
test "expired certificate is rejected" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let root = trust_cert(@fixtures.chain_root_der_hex)
  let message = try {
    let _ = @trust.build_chain(leaf, [intermediate], [root], 2200000000L)
    ""
  } catch {
    e => e.message()
  }
  inspect(message.contains("expired"), content="true")
}

///|
test "not-yet-valid certificate is rejected" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let root = trust_cert(@fixtures.chain_root_der_hex)
  let message = try {
    let _ = @trust.build_chain(leaf, [intermediate], [root], 0L)
    ""
  } catch {
    e => e.message()
  }
  inspect(message.contains("not valid yet"), content="true")
}

///|
test "revoked certificate is rejected" {
  let leaf = trust_cert(@fixtures.chain_leaf_der_hex)
  let intermediate = trust_cert(@fixtures.chain_intermediate_der_hex)
  let root = trust_cert(@fixtures.chain_root_der_hex)
  let crl = @x509.parse_crl(@fixtures.bytes_of_hex(@fixtures.crl_der_hex)) catch {
    _ => abort("failed to parse CRL")
  }
  let message = try {
    let _ = @trust.build_chain_with_crls(
      leaf,
      [intermediate],
      [root],
      [crl],
      1794500000L,
    )
    ""
  } catch {
    e => e.message()
  }
  inspect(message.contains("revoked"), content="true")
}

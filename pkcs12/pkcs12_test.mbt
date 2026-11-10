///|
test "parse a PBES2 PKCS#12 file" {
  let bundle = @pkcs12.parse_pkcs12(
    @fixtures.bytes_of_hex(@fixtures.rsa_p12_der_hex),
    "test",
  ) catch {
    e => fail(e.message())
  }
  inspect(bundle.certificates.length(), content="1")
  inspect(
    @der.der_bytes_compare(
      bundle.certificates[0].der,
      @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
    ) ==
    0,
    content="true",
  )
  let key_der = match bundle.private_key_der {
    Some(value) => value
    None => fail("expected a private key")
  }
  let key = @pem.parse_private_key(key_der) catch {
    _ => fail("failed to parse the decrypted key")
  }
  match key {
    @pem.PrivateKey::Rsa(_, _) => ()
    _ => fail("expected an RSA key")
  }
}

///|
test "wrong PKCS#12 password is rejected" {
  let failed = try {
    let _ = @pkcs12.parse_pkcs12(
      @fixtures.bytes_of_hex(@fixtures.rsa_p12_der_hex),
      "wrong",
    )
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
fn pem_text(label : String, der : Bytes) -> String {
  "-----BEGIN " +
  label +
  "-----\n" +
  @mooncry.base64_encode(der) +
  "\n-----END " +
  label +
  "-----\n"
}

///|
test "parse PEM blocks" {
  let der = @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex)
  let text = "comment before\n" + pem_text("CERTIFICATE", der) + "after\n"
  let blocks = @pem.parse_pem(text) catch { _ => fail("PEM parsing failed") }
  inspect(blocks.length(), content="1")
  inspect(blocks[0].label, content="CERTIFICATE")
  inspect(
    @fixtures.hex_of_bytes(blocks[0].der),
    content=@fixtures.rsa_cert_der_hex,
  )
}

///|
test "parse PKCS#8 RSA key" {
  let der = @fixtures.bytes_of_hex(@fixtures.rsa_key_der_hex)
  let key = @pem.parse_private_key(der) catch {
    _ => fail("PKCS#8 RSA parsing failed")
  }
  match key {
    @pem.PrivateKey::Rsa(modulus, private_exponent) => {
      inspect(@fixtures.hex_of_bytes(modulus), content=@fixtures.rsa_n_hex)
      inspect(
        @fixtures.hex_of_bytes(private_exponent),
        content=@fixtures.rsa_d_hex,
      )
    }
    @pem.PrivateKey::EcdsaP256(_) => fail("expected an RSA key")
  }
}

///|
test "parse PKCS#8 EC key" {
  let der = @fixtures.bytes_of_hex(@fixtures.ec_key_der_hex)
  let key = @pem.parse_private_key(der) catch {
    _ => fail("PKCS#8 EC parsing failed")
  }
  match key {
    @pem.PrivateKey::EcdsaP256(scalar) =>
      inspect(@fixtures.hex_of_bytes(scalar), content=@fixtures.ec_priv_hex)
    @pem.PrivateKey::Rsa(_, _) => fail("expected an EC key")
  }
}

///|
test "parse certificate chain from PEM" {
  let text = pem_text(
    "CERTIFICATE",
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  )
  let certs = @pem.parse_certificates(text) catch {
    _ => fail("certificate parsing failed")
  }
  inspect(certs.length(), content="1")
  inspect(certs[0].spki_algorithm_oid, content="1.2.840.113549.1.1.1")
}

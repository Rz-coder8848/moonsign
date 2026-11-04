///|
fn hex_of(bytes : Bytes) -> String {
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    buf.write_string(bytes[i].to_hex())
  }
  buf.to_string()
}

///|
fn main {
  let message = @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => abort("failed to parse fixture certificate")
  }
  let (modulus, _) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => abort("fixture has no RSA key")
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
    _ => abort("RSA signing failed")
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
  println("HEX:" + hex_of(cms_bytes))
}

///|
test "sha256 fixture" {
  let message = @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
  let digest = @crypto.digest(@crypto.Hash::Sha256, message)
  inspect(
    @fixtures.hex_of_bytes(digest),
    content=@fixtures.fixture_message_sha256_hex,
  )
}

///|
test "rsa sign and verify" {
  let message = @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the RSA fixture certificate")
  }
  let (modulus, exponent) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => fail("expected an RSA public key")
  }
  let signature = @crypto.sign_rsa_pkcs1(
    @crypto.Hash::Sha256,
    message,
    modulus,
    @fixtures.bytes_of_hex(@fixtures.rsa_d_hex),
  ) catch {
    _ => fail("RSA signing failed")
  }
  inspect(
    @crypto.verify_rsa_pkcs1(
      @crypto.Hash::Sha256,
      message,
      signature,
      modulus,
      exponent,
    ),
    content="true",
  )
  let tampered = @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
  let flipped = Array::make(tampered.length(), b'\x00')
  for i in 0..<tampered.length() {
    flipped[i] = tampered[i]
  }
  flipped[0] = (flipped[0].to_int() ^ 0x01).to_byte()
  inspect(
    @crypto.verify_rsa_pkcs1(
      @crypto.Hash::Sha256,
      Bytes::from_array(flipped[:]),
      signature,
      modulus,
      exponent,
    ),
    content="false",
  )
}

///|
test "ecdsa sign and verify" {
  let message = @fixtures.bytes_of_hex(@fixtures.fixture_message_hex)
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.ec_cert_der_hex),
  ) catch {
    _ => fail("failed to parse the EC fixture certificate")
  }
  let public_key = match cert.ec_public_key() {
    Some(point) => point
    None => fail("expected an EC public key")
  }
  let signature = @crypto.sign_ecdsa_p256(
    @crypto.Hash::Sha256,
    message,
    @fixtures.bytes_of_hex(@fixtures.ec_priv_hex),
  ) catch {
    _ => fail("ECDSA signing failed")
  }
  // DER SEQUENCE
  inspect(signature[0].to_int(), content="48")
  inspect(
    @crypto.verify_ecdsa_p256(
      @crypto.Hash::Sha256,
      message,
      signature,
      public_key,
    ),
    content="true",
  )
  let tampered = Array::make(message.length(), b'\x00')
  for i in 0..<message.length() {
    tampered[i] = message[i]
  }
  tampered[0] = (tampered[0].to_int() ^ 0x01).to_byte()
  inspect(
    @crypto.verify_ecdsa_p256(
      @crypto.Hash::Sha256,
      Bytes::from_array(tampered[:]),
      signature,
      public_key,
    ),
    content="false",
  )
}

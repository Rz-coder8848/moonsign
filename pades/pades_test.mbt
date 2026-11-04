///|
fn base_pdf() -> Bytes {
  let document = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => abort("failed to create the minimal PDF")
  }
  @pdflite.pdf_write_document(document) catch {
    _ => abort("failed to serialize the minimal PDF")
  }
}

///|
fn rsa_certificate() -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex)) catch {
    _ => abort("failed to parse the RSA fixture certificate")
  }
}

///|
fn ec_certificate() -> @x509.Certificate {
  @x509.parse_certificate(@fixtures.bytes_of_hex(@fixtures.ec_cert_der_hex)) catch {
    _ => abort("failed to parse the EC fixture certificate")
  }
}

///|
fn rsa_signing_key() -> @pades.SigningKey {
  let cert = rsa_certificate()
  let (modulus, _) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => abort("expected an RSA public key")
  }
  @pades.SigningKey::Rsa(modulus, @fixtures.bytes_of_hex(@fixtures.rsa_d_hex))
}

///|
test "sign and verify RSA PDF" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1793793600L),
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  let outcome = try {
    if @pades.verify_pdf(signed, cert) {
      "valid"
    } else {
      "invalid"
    }
  } catch {
    e => "error: " + e.message()
  }
  inspect(outcome, content="valid")
  let signatures = @pdf.signatures(signed) catch {
    _ => abort("failed to extract signatures")
  }
  inspect(signatures.length(), content="1")
  inspect(signatures[0].field_name, content="Signature1")
  inspect(signatures[0].subfilter, content="ETSI.CAdES.detached")
  inspect(signatures[0].byte_range.length(), content="4")
  inspect(signatures[0].contents.length() > 100, content="true")
}

///|
test "sign and verify ECDSA PDF" {
  let cert = ec_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature2",
    contents_chars: 16384,
    signing_time: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(
    base_pdf(),
    @pades.SigningKey::EcdsaP256(@fixtures.bytes_of_hex(@fixtures.ec_priv_hex)),
    cert,
    [],
    options,
  ) catch {
    _ => abort("ECDSA signing failed")
  }
  let outcome = try {
    if @pades.verify_pdf(signed, cert) {
      "valid"
    } else {
      "invalid"
    }
  } catch {
    e => "error: " + e.message()
  }
  inspect(outcome, content="valid")
}

///|
test "tampering invalidates the signature" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  let tampered = Array::make(signed.length(), b'\x00')
  for i in 0..<signed.length() {
    tampered[i] = signed[i]
  }
  tampered[10] = (tampered[10].to_int() ^ 0x01).to_byte()
  inspect(
    @pades.verify_pdf(Bytes::from_array(tampered[:]), cert) catch {
      _ => false
    },
    content="false",
  )
}

///|
test "wrong certificate fails verification" {
  let cert = rsa_certificate()
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(base_pdf(), rsa_signing_key(), cert, [], options) catch {
    _ => abort("signing failed")
  }
  inspect(
    @pades.verify_pdf(signed, ec_certificate()) catch {
      _ => false
    },
    content="false",
  )
}

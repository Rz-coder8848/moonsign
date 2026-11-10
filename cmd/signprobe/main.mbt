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
  let base = @pdflite.pdf_minimum_valid_pdf() catch { _ => abort("minimal") }
  let bytes = @pdflite.pdf_write_document(base) catch { _ => abort("write") }
  let cert = @x509.parse_certificate(
    @fixtures.bytes_of_hex(@fixtures.rsa_cert_der_hex),
  ) catch {
    _ => abort("cert")
  }
  let (modulus, _) = match cert.rsa_public_key() {
    Some(pair) => pair
    None => abort("rsa key")
  }
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1793793600L),
    reason: None,
    location: None,
    contact: None,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(
    bytes,
    @pades.SigningKey::Rsa(modulus, @fixtures.bytes_of_hex(@fixtures.rsa_d_hex)),
    cert,
    [],
    options,
  ) catch {
    _ => abort("sign")
  }
  println("PDF:" + hex_of(signed))
}

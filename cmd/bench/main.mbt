///|
/// Sign and verify PDFs of increasing size, printing timings.
///
/// The output is intentionally simple so CI logs can be copied into
/// docs/PERFORMANCE.md.
fn main {
  let cert = @x509.parse_certificate(
    @testdata.bytes_of_hex(@testdata.rsa_cert_der_hex),
  ) catch {
    _ => abort("failed to parse the benchmark certificate")
  }
  let key = @pem.parse_private_key(
    @testdata.bytes_of_hex(@testdata.rsa_key_der_hex),
  ) catch {
    _ => abort("failed to parse the benchmark key")
  }
  let (modulus, private_exponent) = match key {
    @pem.PrivateKey::Rsa(n, d) => (n, d)
    _ => abort("expected an RSA key")
  }
  let options : @pades.SignOptions = {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: Some(1794500000L),
    reason: None,
    location: None,
    contact: None,
    appearance: None,
    hash: @crypto.Hash::Sha256,
  }
  println("pages,bytes,sign_ms,verify_ms")
  for pages in [1, 500, 2000, 5000, 10000] {
    let pdf = @pdf.paged_pdf(pages)
    let start = @env.now().reinterpret_as_int64()
    let signed = @pades.sign_pdf(
      pdf,
      @pades.SigningKey::Rsa(modulus, private_exponent),
      cert,
      [],
      options,
    ) catch {
      e => abort("sign failed: " + e.message())
    }
    let signed_at = @env.now().reinterpret_as_int64()
    let valid = @pades.verify_pdf(signed, cert) catch { _ => false }
    let verified_at = @env.now().reinterpret_as_int64()
    if !valid {
      abort("verification failed for " + pages.to_string() + " pages")
    }
    let sign_ms = signed_at - start
    let verify_ms = verified_at - signed_at
    println(
      pages.to_string() +
      "," +
      signed.length().to_string() +
      "," +
      sign_ms.to_string() +
      "," +
      verify_ms.to_string(),
    )
    if sign_ms > 120000 {
      abort("signing took longer than 120 seconds")
    }
  }
}

///|
/// Errors reported by the command-line layer.
pub(all) suberror CliError {
  Failure(String)
}

///|
fn message_of(error : CliError) -> String {
  match error {
    Failure(value) => value
  }
}

///|
fn usage() -> Unit {
  println("moonsign - PDF digital signatures (PAdES B-B)")
  println("")
  println("Usage:")
  println(
    "  moonsign sign <in.pdf> --key <key.pem> --cert <cert.pem> [options]",
  )
  println("  moonsign verify <in.pdf> --cert <cert.pem> [--json]")
  println("  moonsign verify <in.pdf> --anchors <ca.pem> [--json]")
  println("  moonsign info <in.pdf> [--json]")
  println("  moonsign tsa-request <signed.pdf> --out <request.der>")
  println(
    "  moonsign tsa-embed <signed.pdf> --response <response.der> --out <out.pdf>",
  )
  println("")
  println(
    "Timestamp (RFC 3161): create a request, POST it to a TSA, then embed",
  )
  println("the response. The signature itself is not changed.")
  println("")
  println("Sign options:")
  println("  --out <path>      output PDF (default: <in>.signed.pdf)")
  println("  --chain <path>    extra certificates to embed during signing")
  println("  --anchors <path>  trust anchors used to check the signer chain")
  println("  --crl <path>      CRLs (PEM) used to check revocation")
  println("  --tsa-anchors <path>  trust anchors for the timestamp (B-T)")
  println("  --ocsp <path>     OCSP response (DER) to check revocation")
  println("  --p12 <path>      PKCS#12 file (instead of --key/--cert)")
  println(
    "  --p12-password <text>  PKCS#12 password (or MOONSIGN_P12_PASSWORD)",
  )
  println("  --field <name>    signature field name (default: Signature1)")
  println("  --reason <text>   reason recorded in the signature dictionary")
  println("  --location <text> signing location")
  println("  --contact <text>  signer contact information")
  println("  --signing-time <unix seconds>  override the signing time")
  println("  --json            machine-readable summary")
  println("")
  println("Exit codes: 0 ok/valid, 2 invalid signature, 3 valid but untrusted,")
  println("            1 usage or I/O error")
}

///|
fn is_command(value : String) -> Bool {
  value == "sign" ||
  value == "verify" ||
  value == "info" ||
  value == "tsa-request" ||
  value == "tsa-embed" ||
  value == "help" ||
  value == "--help" ||
  value == "-h"
}

///|
pub(all) struct CliOptions {
  mut input : String?
  mut out : String?
  mut key : String?
  mut cert : String?
  mut chain : String?
  mut anchors : String?
  mut crl : String?
  mut field : String
  mut reason : String?
  mut location : String?
  mut contact : String?
  mut signing_time : String?
  mut response : String?
  mut tsa_anchors : String?
  mut ocsp : String?
  mut p12 : String?
  mut p12_password : String?
  mut json : Bool
}

///|
fn is_flag(value : String) -> Bool {
  match value.get_char(0) {
    Some(c) => c == '-'
    None => false
  }
}

///|
fn parse_options(args : Array[String]) -> CliOptions raise CliError {
  let options : CliOptions = {
    input: None,
    out: None,
    key: None,
    cert: None,
    chain: None,
    anchors: None,
    crl: None,
    field: "Signature1",
    reason: None,
    location: None,
    contact: None,
    signing_time: None,
    response: None,
    tsa_anchors: None,
    ocsp: None,
    p12: None,
    p12_password: None,
    json: false,
  }
  let mut index = 0
  while index < args.length() {
    let arg = args[index]
    if arg == "--json" {
      options.json = true
      index = index + 1
    } else if arg == "--out" ||
      arg == "--key" ||
      arg == "--cert" ||
      arg == "--chain" ||
      arg == "--anchors" ||
      arg == "--crl" ||
      arg == "--field" ||
      arg == "--reason" ||
      arg == "--location" ||
      arg == "--contact" ||
      arg == "--signing-time" ||
      arg == "--response" ||
      arg == "--tsa-anchors" ||
      arg == "--ocsp" ||
      arg == "--p12" ||
      arg == "--p12-password" {
      if index + 1 >= args.length() {
        raise CliError::Failure("missing value for " + arg)
      }
      let value = args[index + 1]
      if arg == "--out" {
        options.out = Some(value)
      } else if arg == "--key" {
        options.key = Some(value)
      } else if arg == "--cert" {
        options.cert = Some(value)
      } else if arg == "--chain" {
        options.chain = Some(value)
      } else if arg == "--anchors" {
        options.anchors = Some(value)
      } else if arg == "--crl" {
        options.crl = Some(value)
      } else if arg == "--reason" {
        options.reason = Some(value)
      } else if arg == "--location" {
        options.location = Some(value)
      } else if arg == "--contact" {
        options.contact = Some(value)
      } else if arg == "--signing-time" {
        options.signing_time = Some(value)
      } else if arg == "--response" {
        options.response = Some(value)
      } else if arg == "--tsa-anchors" {
        options.tsa_anchors = Some(value)
      } else if arg == "--ocsp" {
        options.ocsp = Some(value)
      } else if arg == "--p12" {
        options.p12 = Some(value)
      } else if arg == "--p12-password" {
        options.p12_password = Some(value)
      } else {
        options.field = value
      }
      index = index + 2
    } else if is_flag(arg) {
      raise CliError::Failure("unknown option: " + arg)
    } else {
      let has_input = match options.input {
        Some(_) => true
        None => false
      }
      if has_input {
        raise CliError::Failure("unexpected extra argument: " + arg)
      }
      options.input = Some(arg)
      index = index + 1
    }
  }
  options
}

///|
fn require(value : String?, name : String) -> String raise CliError {
  match value {
    Some(path) => path
    None => raise CliError::Failure("missing required " + name)
  }
}

///|
fn read_bytes(path : String) -> Bytes raise CliError {
  @fs.read_file_to_bytes(path) catch {
    _ => raise CliError::Failure("cannot read file: " + path)
  }
}

///|
fn read_text(path : String) -> String raise CliError {
  @fs.read_file_to_string(path) catch {
    _ => raise CliError::Failure("cannot read file: " + path)
  }
}

///|
fn write_bytes(path : String, bytes : Bytes) -> Unit raise CliError {
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => raise CliError::Failure("cannot write file: " + path)
  }
}

///|
fn json_escape(value : String) -> String {
  let buf = StringBuilder()
  for c in value.iter() {
    if c == '"' {
      buf.write_string("\\\"")
    } else if c == '\\' {
      buf.write_string("\\\\")
    } else {
      buf.write_char(c)
    }
  }
  buf.to_string()
}

///|
fn default_output(input : String) -> String {
  input + ".signed.pdf"
}

///|
fn signing_key_of(key : @pem.PrivateKey) -> @pades.SigningKey {
  match key {
    @pem.PrivateKey::Rsa(modulus, private_exponent) =>
      @pades.SigningKey::Rsa(modulus, private_exponent)
    @pem.PrivateKey::EcdsaP256(scalar) => @pades.SigningKey::EcdsaP256(scalar)
  }
}

///|
fn load_material(
  options : CliOptions,
) -> (@pades.SigningKey, @x509.Certificate, Array[Bytes]) raise CliError {
  let (key, leaf, extra) = match options.p12 {
    Some(path) => {
      let password = match options.p12_password {
        Some(value) => value
        None =>
          match @env.get_env_var("MOONSIGN_P12_PASSWORD") {
            Some(value) => value
            None =>
              raise CliError::Failure(
                "--p12 needs --p12-password or MOONSIGN_P12_PASSWORD",
              )
          }
      }
      let p12_bytes = read_bytes(path)
      let bundle = @pkcs12.parse_pkcs12(p12_bytes, password) catch {
        e => raise CliError::Failure("cannot parse PKCS#12: " + e.message())
      }
      if bundle.certificates.length() == 0 {
        raise CliError::Failure("PKCS#12 file has no certificate")
      }
      let key_der = match bundle.private_key_der {
        Some(value) => value
        None => raise CliError::Failure("PKCS#12 file has no private key")
      }
      let private_key = @pem.parse_private_key(key_der) catch {
        e => raise CliError::Failure("cannot parse PKCS#12 key: " + e.message())
      }
      let extras : Array[Bytes] = []
      for i in 1..<bundle.certificates.length() {
        extras.push(bundle.certificates[i].der)
      }
      (private_key, bundle.certificates[0], extras)
    }
    None => {
      let key_path = require(options.key, "private key (--key)")
      let cert_path = require(options.cert, "certificate (--cert)")
      let key_text = read_text(key_path)
      let cert_text = read_text(cert_path)
      let key_blocks = @pem.parse_pem(key_text) catch {
        e => raise CliError::Failure("cannot parse key PEM: " + e.message())
      }
      let mut private_key : @pem.PrivateKey? = None
      for block in key_blocks {
        if block.label.contains("PRIVATE KEY") {
          let parsed = @pem.parse_private_key(block.der) catch {
            e =>
              raise CliError::Failure(
                "cannot parse private key: " + e.message(),
              )
          }
          private_key = Some(parsed)
          break
        }
      }
      let key = match private_key {
        Some(value) => value
        None =>
          raise CliError::Failure("no private key block found in " + key_path)
      }
      let certs = @pem.parse_certificates(cert_text) catch {
        e => raise CliError::Failure("cannot parse certificate: " + e.message())
      }
      if certs.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + cert_path)
      }
      let extras : Array[Bytes] = []
      for i in 1..<certs.length() {
        extras.push(certs[i].der)
      }
      (key, certs[0], extras)
    }
  }
  match options.chain {
    Some(path) => {
      let chain_text = read_text(path)
      let chain_certs = @pem.parse_certificates(chain_text) catch {
        e => raise CliError::Failure("cannot parse chain: " + e.message())
      }
      for cert in chain_certs {
        extra.push(cert.der)
      }
    }
    None => ()
  }
  (signing_key_of(key), leaf, extra)
}

///|
fn sign_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let out_path = match options.out {
    Some(path) => path
    None => default_output(input)
  }
  let pdf_bytes = read_bytes(input)
  let (signing_key, leaf, extra) = load_material(options)
  let signing_time = match options.signing_time {
    Some(text) => parse_unix(text)
    None => now_seconds()
  }
  let sign_options : @pades.SignOptions = {
    field_name: options.field,
    contents_chars: 16384,
    signing_time: Some(signing_time),
    reason: options.reason,
    location: options.location,
    contact: options.contact,
    hash: @crypto.Hash::Sha256,
  }
  let signed = @pades.sign_pdf(
    pdf_bytes, signing_key, leaf, extra, sign_options,
  ) catch {
    e => raise CliError::Failure(e.message())
  }
  write_bytes(out_path, signed)
  if options.json {
    println(
      "{\"command\":\"sign\",\"ok\":true,\"out\":\"" +
      json_escape(out_path) +
      "\",\"field\":\"" +
      json_escape(options.field) +
      "\"}",
    )
  } else {
    println("Signed: " + out_path)
    println("Field: " + options.field)
    println("Digest: SHA-256")
  }
}

///|

///|
fn read_crls(path : String) -> Array[@x509.Crl] raise CliError {
  let text = read_text(path)
  let blocks = @pem.parse_pem(text) catch {
    e => raise CliError::Failure("cannot parse CRL PEM: " + e.message())
  }
  let out : Array[@x509.Crl] = []
  for block in blocks {
    if block.label == "X509 CRL" {
      let crl = @x509.parse_crl(block.der) catch {
        e => raise CliError::Failure("cannot parse CRL: " + e.message())
      }
      out.push(crl)
    }
  }
  if out.length() == 0 {
    raise CliError::Failure("no X509 CRL block found in " + path)
  }
  out
}

///|
fn now_seconds() -> Int64 {
  let raw = @env.now().reinterpret_as_int64()
  if raw > 100000000000L {
    raw / 1000L
  } else {
    raw
  }
}

///|
fn parse_unix(text : String) -> Int64 raise CliError {
  if text.length() == 0 {
    raise CliError::Failure("invalid --signing-time")
  }
  let mut value = 0L
  for i in 0..<text.length() {
    match text.get_char(i) {
      Some(c) => {
        let digit = c.to_int() - 48
        if digit < 0 || digit > 9 {
          raise CliError::Failure("invalid --signing-time: " + text)
        }
        value = value * 10L + Int64::from_int(digit)
      }
      None => raise CliError::Failure("invalid --signing-time: " + text)
    }
  }
  value
}

///|
fn report_timestamp(
  pdf_bytes : Bytes,
  tsa_anchors_path : String?,
) -> Unit raise CliError {
  let anchors = match tsa_anchors_path {
    Some(path) => {
      let text = read_text(path)
      @pem.parse_certificates(text) catch {
        e => raise CliError::Failure("cannot parse TSA anchors: " + e.message())
      }
    }
    None => []
  }
  let outcome = @pades.verify_timestamp_at(pdf_bytes, 0, anchors, now_seconds()) catch {
    _ => return
  }
  if !outcome.present {
    return
  }
  if !outcome.valid {
    println("  timestamp: INVALID")
    match outcome.error {
      Some(message) => println("    " + message)
      None => ()
    }
  } else {
    match outcome.chain {
      Some(chain) =>
        println(
          "  timestamp: VALID and TRUSTED (" +
          chain.certificates.length().to_string() +
          " certificates)",
        )
      None => println("  timestamp: VALID (TSA chain not checked)")
    }
  }
}

///|
fn verify_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let pdf_bytes = read_bytes(input)
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise CliError::Failure("no signature found in " + input)
  }
  let cert_path = options.cert
  let anchors_path = options.anchors
  if cert_path is None && anchors_path is None {
    raise CliError::Failure("verify needs --cert <pem> or --anchors <pem>")
  }
  match anchors_path {
    Some(path) => {
      let anchors_text = read_text(path)
      let anchors = @pem.parse_certificates(anchors_text) catch {
        e => raise CliError::Failure("cannot parse anchors: " + e.message())
      }
      if anchors.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      let crls = match options.crl {
        Some(path) => read_crls(path)
        None => []
      }
      let outcome = @pades.verify_pdf_with_anchors_and_crls(
        pdf_bytes,
        anchors,
        crls,
        now_seconds(),
      ) catch {
        e => raise CliError::Failure(e.message())
      }
      let trusted = match outcome.chain {
        Some(_) => true
        None => false
      }
      if options.json {
        let buf = StringBuilder()
        buf.write_string("{\"command\":\"verify\",\"valid\":")
        buf.write_string(if outcome.signature_valid { "true" } else { "false" })
        buf.write_string(",\"trusted\":")
        buf.write_string(if trusted { "true" } else { "false" })
        buf.write_string(",\"signatures\":")
        buf.write_string(signatures.length().to_string())
        buf.write_string(",\"field\":\"")
        buf.write_string(json_escape(signatures[0].field_name))
        buf.write_string("\"")
        match outcome.chain {
          Some(chain) => {
            buf.write_string(",\"chain_length\":")
            buf.write_string(chain.certificates.length().to_string())
          }
          None => ()
        }
        match outcome.trust_error {
          Some(message) => {
            buf.write_string(",\"trust_error\":\"")
            buf.write_string(json_escape(message))
            buf.write_string("\"")
          }
          None => ()
        }
        buf.write_string("}")
        println(buf.to_string())
      } else {
        println("Signature 1: " + signatures[0].field_name)
        println("  subfilter: " + signatures[0].subfilter)
        if !outcome.signature_valid {
          println("Result: INVALID")
          println("  The document changed, or the signature does not verify.")
        } else if trusted {
          println("Result: VALID and TRUSTED")
          match outcome.chain {
            Some(chain) =>
              println(
                "  Certificate chain: " +
                chain.certificates.length().to_string() +
                " certificates, ending at a trust anchor you supplied.",
              )
            None => ()
          }
        } else {
          println("Result: VALID but NOT TRUSTED")
          println("  The signature is intact, but no chain to your anchor.")
          match outcome.trust_error {
            Some(message) => println("  reason: " + message)
            None => ()
          }
        }
      }
      report_timestamp(pdf_bytes, options.tsa_anchors)
      let mut ocsp_revoked = false
      match options.ocsp {
        Some(path) => {
          let mut report = "  OCSP: skipped (no issuer certificate in the chain)"
          match outcome.signer {
            Some(signer) =>
              match outcome.chain {
                Some(chain) =>
                  if chain.certificates.length() >= 2 {
                    let issuer = chain.certificates[1]
                    let bytes = read_bytes(path)
                    let response = @ocsp.parse_response(bytes) catch {
                      e =>
                        raise CliError::Failure(
                          "cannot parse OCSP response: " + e.message(),
                        )
                    }
                    let status = @ocsp.check(
                      response,
                      signer,
                      issuer,
                      now_seconds(),
                    ) catch {
                      e =>
                        raise CliError::Failure(
                          "OCSP check failed: " + e.message(),
                        )
                    }
                    match status {
                      @ocsp.CertStatus::Good => report = "  OCSP: good"
                      @ocsp.CertStatus::Revoked(at) => {
                        report = "  OCSP: REVOKED at " + at.to_string()
                        ocsp_revoked = true
                      }
                      @ocsp.CertStatus::Unknown => report = "  OCSP: unknown"
                    }
                  }
                None => ()
              }
            None => ()
          }
          println(report)
        }
        None => ()
      }
      if !outcome.signature_valid {
        @env.exit(2)
      }
      if !trusted || ocsp_revoked {
        @env.exit(3)
      }
    }
    None => {
      let path = match cert_path {
        Some(value) => value
        None => raise CliError::Failure("verify needs --cert or --anchors")
      }
      let cert_text = read_text(path)
      let certs = @pem.parse_certificates(cert_text) catch {
        e => raise CliError::Failure("cannot parse certificate: " + e.message())
      }
      if certs.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      let valid = @pades.verify_pdf(pdf_bytes, certs[0]) catch {
        e => raise CliError::Failure(e.message())
      }
      if options.json {
        println(
          "{\"command\":\"verify\",\"valid\":" +
          (if valid { "true" } else { "false" }) +
          ",\"signatures\":" +
          signatures.length().to_string() +
          ",\"field\":\"" +
          json_escape(signatures[0].field_name) +
          "\"}",
        )
      } else {
        println("Signature 1: " + signatures[0].field_name)
        println("  subfilter: " + signatures[0].subfilter)
        if valid {
          println("Result: VALID")
          println("  The document has not changed since signing.")
          println(
            "  (Trust in the certificate is your decision: pass the right one.)",
          )
        } else {
          println("Result: INVALID")
          println("  The document changed, or the certificate does not match.")
        }
      }
      report_timestamp(pdf_bytes, options.tsa_anchors)
      if options.ocsp is Some(_) {
        println("  OCSP: skipped (use --anchors so the issuer is available)")
      }
      if !valid {
        @env.exit(2)
      }
    }
  }
}

///|
fn info_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let pdf_bytes = read_bytes(input)
  let signatures = @pdf.find_signatures(pdf_bytes)
  if options.json {
    let buf = StringBuilder()
    buf.write_string("{\"command\":\"info\",\"signatures\":[")
    for i in 0..<signatures.length() {
      if i > 0 {
        buf.write_string(",")
      }
      buf.write_string("{\"field\":\"")
      buf.write_string(json_escape(signatures[i].field_name))
      buf.write_string("\",\"subfilter\":\"")
      buf.write_string(json_escape(signatures[i].subfilter))
      buf.write_string("\",\"contents_bytes\":")
      buf.write_string(signatures[i].contents.length().to_string())
      buf.write_string(",\"byte_range\":[")
      for j in 0..<signatures[i].byte_range.length() {
        if j > 0 {
          buf.write_string(",")
        }
        buf.write_string(signatures[i].byte_range[j].to_string())
      }
      buf.write_string("]}")
    }
    buf.write_string("]}")
    println(buf.to_string())
  } else if signatures.length() == 0 {
    println("No signature found.")
  } else {
    println("Signatures: " + signatures.length().to_string())
    for i in 0..<signatures.length() {
      println(
        "  [" +
        (i + 1).to_string() +
        "] " +
        signatures[i].field_name +
        "  subfilter=" +
        signatures[i].subfilter +
        "  reserved=" +
        signatures[i].contents.length().to_string() +
        " bytes",
      )
      let ranges = StringBuilder()
      for j in 0..<signatures[i].byte_range.length() {
        if j > 0 {
          ranges.write_string(" ")
        }
        ranges.write_string(signatures[i].byte_range[j].to_string())
      }
      println("      byteRange: [" + ranges.to_string() + "]")
    }
  }
}

///|
fn tsa_request_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let out = require(options.out, "--out (timestamp request)")
  let pdf_bytes = read_bytes(input)
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise CliError::Failure("no signature found in " + input)
  }
  let signed_data = @cms.parse_signed_data(signatures[0].contents) catch {
    e => raise CliError::Failure(e.message())
  }
  if signed_data.signer_infos.length() == 0 {
    raise CliError::Failure("CMS has no signer")
  }
  let signer = signed_data.signer_infos[0]
  let hash = match @crypto.Hash::from_oid(signer.digest_oid) {
    Some(value) => value
    None => raise CliError::Failure("unsupported digest: " + signer.digest_oid)
  }
  let request = @tsa.build_request(signer.signature, hash, true)
  write_bytes(out, request)
  println("Timestamp request: " + out)
}

///|
fn tsa_embed_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let response_path = require(
    options.response,
    "--response (timestamp response)",
  )
  let out = require(options.out, "--out (timestamped PDF)")
  let pdf_bytes = read_bytes(input)
  let response = read_bytes(response_path)
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise CliError::Failure("no signature found in " + input)
  }
  let signed_data = @cms.parse_signed_data(signatures[0].contents) catch {
    e => raise CliError::Failure(e.message())
  }
  if signed_data.signer_infos.length() == 0 {
    raise CliError::Failure("CMS has no signer")
  }
  let signer = signed_data.signer_infos[0]
  let hash = match @crypto.Hash::from_oid(signer.digest_oid) {
    Some(value) => value
    None => raise CliError::Failure("unsupported digest: " + signer.digest_oid)
  }
  let parsed = @tsa.parse_response(response) catch {
    e => raise CliError::Failure(e.message())
  }
  let token = match parsed.token {
    Some(value) => value
    None => raise CliError::Failure("timestamp response contains no token")
  }
  if !@tsa.verify_token(token, signer.signature, hash) {
    raise CliError::Failure("timestamp token does not match this signature")
  }
  match options.anchors {
    Some(path) => {
      let anchors_text = read_text(path)
      let anchors = @pem.parse_certificates(anchors_text) catch {
        e => raise CliError::Failure("cannot parse TSA anchors: " + e.message())
      }
      if anchors.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      let chain = @tsa.verify_token_chain(token, anchors, now_seconds()) catch {
        e => raise CliError::Failure(e.message())
      }
      println(
        "TSA chain: " +
        chain.certificates.length().to_string() +
        " certificates (trusted)",
      )
    }
    None =>
      println(
        "Note: TSA certificate chain not checked (pass --anchors <tsa-ca.pem>).",
      )
  }
  let signer_cert = match @cms.signer_certificate(signed_data, signer) {
    Some(value) => value
    None => raise CliError::Failure("signer certificate is missing")
  }
  let extra : Array[Bytes] = []
  for cert in signed_data.certificates {
    if @der.der_bytes_compare(cert, signer_cert.der) != 0 {
      extra.push(cert)
    }
  }
  let attrs_raw = signer.signed_attrs_raw
  let attrs = Array::make(attrs_raw.length(), b'\x00')
  for i in 0..<attrs_raw.length() {
    attrs[i] = attrs_raw[i]
  }
  if attrs.length() > 0 {
    attrs[0] = b'\x31'
  }
  let cms_bytes = @cms.assemble_signed_data(
    Bytes::from_array(attrs[:]),
    signer.signature,
    hash,
    signer.signature_oid,
    signer_cert,
    extra,
    signed_data.content_type,
    timestamp_token=token,
  )
  let stamped = @pdf.replace_contents(pdf_bytes, cms_bytes) catch {
    e => raise CliError::Failure(e.message())
  }
  write_bytes(out, stamped)
  println("Timestamped: " + out)
}

///|
fn run(command : String, args : Array[String]) -> Unit {
  let result : Result[Unit, String] = try {
    if command == "sign" {
      sign_impl(args)
    } else if command == "verify" {
      verify_impl(args)
    } else if command == "tsa-request" {
      tsa_request_impl(args)
    } else if command == "tsa-embed" {
      tsa_embed_impl(args)
    } else {
      info_impl(args)
    }
    Ok(())
  } catch {
    e => Err(message_of(e))
  }
  match result {
    Ok(_) => ()
    Err(message) => {
      println("moonsign: " + message)
      @env.exit(1)
    }
  }
}

///|
fn main {
  let all = @env.args()
  let mut index = 0
  while index < all.length() && !is_command(all[index]) {
    index = index + 1
  }
  if index >= all.length() {
    usage()
    return
  }
  let command = all[index]
  if command == "help" || command == "--help" || command == "-h" {
    usage()
    return
  }
  let rest : Array[String] = []
  for i in (index + 1)..<all.length() {
    rest.push(all[i])
  }
  run(command, rest)
}

///|
struct VerifyReport {
  index : Int32
  field : String
  subfilter : String
  valid : Bool
  trusted : Bool?
  chain_length : Int32?
  trust_error : String?
  timestamp_present : Bool
  timestamp_valid : Bool
  timestamp_detail : String?
  ocsp : String?
}

///|
fn verify_one(
  pdf_bytes : Bytes,
  index : Int32,
  signatures : Array[@pdf.PdfSignature],
  options : CliOptions,
  certs : Array[@x509.Certificate]?,
  anchors : Array[@x509.Certificate]?,
  crls : Array[@x509.Crl],
  tsa_anchors : Array[@x509.Certificate],
  now : Int64,
) -> VerifyReport raise CliError {
  let signature = signatures[index]
  let mut valid = false
  let mut trusted : Bool? = None
  let mut chain_length : Int32? = None
  let mut trust_error : String? = None
  let mut signer : @x509.Certificate? = None
  let mut issuer : @x509.Certificate? = None
  match anchors {
    Some(list) => {
      let outcome = @pades.verify_pdf_with_anchors_and_crls_at(
        pdf_bytes, index, list, crls, now,
      ) catch {
        e => raise CliError::Failure(e.message())
      }
      valid = outcome.signature_valid
      signer = outcome.signer
      match outcome.chain {
        Some(chain) => {
          trusted = Some(true)
          chain_length = Some(chain.certificates.length())
          if chain.certificates.length() >= 2 {
            issuer = Some(chain.certificates[1])
          }
        }
        None => {
          trusted = Some(false)
          trust_error = outcome.trust_error
        }
      }
    }
    None => {
      let list = match certs {
        Some(value) => value
        None => raise CliError::Failure("verify needs --cert or --anchors")
      }
      valid = @pades.verify_pdf_at(pdf_bytes, index, list[0]) catch {
        e => raise CliError::Failure(e.message())
      }
    }
  }
  let mut timestamp_present = false
  let mut timestamp_valid = false
  let mut timestamp_detail : String? = None
  let timestamp = Some(
    @pades.verify_timestamp_at(pdf_bytes, index, tsa_anchors, now),
  ) catch {
    _ => None
  }
  match timestamp {
    Some(outcome) => {
      timestamp_present = outcome.present
      timestamp_valid = outcome.valid
      if outcome.present {
        if !outcome.valid {
          timestamp_detail = Some("INVALID")
        } else {
          match outcome.chain {
            Some(chain) =>
              timestamp_detail = Some(
                "VALID and TRUSTED (" +
                chain.certificates.length().to_string() +
                " certificates)",
              )
            None => timestamp_detail = Some("VALID (TSA chain not checked)")
          }
        }
      }
    }
    None => ()
  }
  let mut ocsp_status : String? = None
  match options.ocsp {
    Some(path) =>
      match signer {
        Some(cert) =>
          match issuer {
            Some(issuer_cert) => {
              let bytes = read_bytes(path)
              let response = @ocsp.parse_response(bytes) catch {
                e =>
                  raise CliError::Failure(
                    "cannot parse OCSP response: " + e.message(),
                  )
              }
              let status = @ocsp.check(response, cert, issuer_cert, now) catch {
                e =>
                  raise CliError::Failure("OCSP check failed: " + e.message())
              }
              ocsp_status = Some(
                match status {
                  @ocsp.CertStatus::Good => "good"
                  @ocsp.CertStatus::Revoked(_) => "revoked"
                  @ocsp.CertStatus::Unknown => "unknown"
                },
              )
            }
            None => ocsp_status = Some("skipped (no issuer in chain)")
          }
        None => ocsp_status = Some("skipped (no signer)")
      }
    None => ()
  }
  {
    index,
    field: signature.field_name,
    subfilter: signature.subfilter,
    valid,
    trusted,
    chain_length,
    trust_error,
    timestamp_present,
    timestamp_valid,
    timestamp_detail,
    ocsp: ocsp_status,
  }
}

///|
fn print_verify_report(report : VerifyReport) -> Unit {
  println("Signature " + (report.index + 1).to_string() + ": " + report.field)
  println("  subfilter: " + report.subfilter)
  if !report.valid {
    println("Result: INVALID")
    println("  The document changed, or the signature does not verify.")
  } else {
    match report.trusted {
      Some(true) => {
        println("Result: VALID and TRUSTED")
        match report.chain_length {
          Some(length) =>
            println(
              "  Certificate chain: " +
              length.to_string() +
              " certificates, ending at a trust anchor you supplied.",
            )
          None => ()
        }
      }
      Some(false) => {
        println("Result: VALID but NOT TRUSTED")
        println("  The signature is intact, but no chain to your anchor.")
        match report.trust_error {
          Some(message) => println("  reason: " + message)
          None => ()
        }
      }
      None => {
        println("Result: VALID")
        println("  The document has not changed since signing.")
        println(
          "  (Trust in the certificate is your decision: pass the right one.)",
        )
      }
    }
  }
  if report.timestamp_present {
    match report.timestamp_detail {
      Some(detail) => println("  timestamp: " + detail)
      None => println("  timestamp: present")
    }
  }
  match report.ocsp {
    Some(status) => println("  OCSP: " + status)
    None => ()
  }
}

///|
fn verify_all_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let pdf_bytes = read_bytes(input)
  let signatures = @pdf.find_signatures(pdf_bytes)
  if signatures.length() == 0 {
    raise CliError::Failure("no signature found in " + input)
  }
  let certs : Array[@x509.Certificate]? = match options.cert {
    Some(path) => {
      let text = read_text(path)
      let parsed = @pem.parse_certificates(text) catch {
        e => raise CliError::Failure("cannot parse certificate: " + e.message())
      }
      if parsed.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      Some(parsed)
    }
    None => None
  }
  let anchors : Array[@x509.Certificate]? = match options.anchors {
    Some(path) => {
      let text = read_text(path)
      let parsed = @pem.parse_certificates(text) catch {
        e => raise CliError::Failure("cannot parse anchors: " + e.message())
      }
      if parsed.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      Some(parsed)
    }
    None => None
  }
  if certs is None && anchors is None {
    raise CliError::Failure("verify needs --cert <pem> or --anchors <pem>")
  }
  let crls = match options.crl {
    Some(path) => read_crls(path)
    None => []
  }
  let tsa_anchors : Array[@x509.Certificate] = match options.tsa_anchors {
    Some(path) => {
      let text = read_text(path)
      let parsed = @pem.parse_certificates(text) catch {
        e => raise CliError::Failure("cannot parse TSA anchors: " + e.message())
      }
      if parsed.length() == 0 {
        raise CliError::Failure("no CERTIFICATE block found in " + path)
      }
      parsed
    }
    None => []
  }
  let indices : Array[Int32] = match options.signature_index {
    Some(text) => {
      let selected = parse_unix(text).to_int()
      if selected < 1 || selected > signatures.length() {
        raise CliError::Failure("signature number out of range")
      }
      [selected - 1]
    }
    None => {
      let all : Array[Int32] = []
      for i in 0..<signatures.length() {
        all.push(i)
      }
      all
    }
  }
  let now = now_seconds()
  let reports : Array[VerifyReport] = []
  for index in indices {
    reports.push(
      verify_one(
        pdf_bytes, index, signatures, options, certs, anchors, crls, tsa_anchors,
        now,
      ),
    )
  }
  let mut any_invalid = false
  let mut any_untrusted = false
  let mut any_revoked = false
  for report in reports {
    if !report.valid {
      any_invalid = true
    }
    match report.trusted {
      Some(false) => any_untrusted = true
      _ => ()
    }
    match report.ocsp {
      Some(status) => if status == "revoked" { any_revoked = true }
      None => ()
    }
  }
  if options.json {
    let buf = StringBuilder()
    buf.write_string("{\"command\":\"verify\",\"signature_count\":")
    buf.write_string(signatures.length().to_string())
    buf.write_string(",\"results\":[")
    for i in 0..<reports.length() {
      if i > 0 {
        buf.write_string(",")
      }
      let report = reports[i]
      buf.write_string("{\"index\":")
      buf.write_string((report.index + 1).to_string())
      buf.write_string(",\"field\":\"")
      buf.write_string(json_escape(report.field))
      buf.write_string("\",\"valid\":")
      buf.write_string(if report.valid { "true" } else { "false" })
      match report.trusted {
        Some(value) => {
          buf.write_string(",\"trusted\":")
          buf.write_string(if value { "true" } else { "false" })
        }
        None => ()
      }
      match report.chain_length {
        Some(length) => {
          buf.write_string(",\"chain_length\":")
          buf.write_string(length.to_string())
        }
        None => ()
      }
      match report.trust_error {
        Some(message) => {
          buf.write_string(",\"trust_error\":\"")
          buf.write_string(json_escape(message))
          buf.write_string("\"")
        }
        None => ()
      }
      if report.timestamp_present {
        buf.write_string(",\"timestamp\":{\"present\":true,\"valid\":")
        buf.write_string(if report.timestamp_valid { "true" } else { "false" })
        match report.timestamp_detail {
          Some(detail) => {
            buf.write_string(",\"detail\":\"")
            buf.write_string(json_escape(detail))
            buf.write_string("\"")
          }
          None => ()
        }
        buf.write_string("}")
      }
      match report.ocsp {
        Some(status) => {
          buf.write_string(",\"ocsp\":\"")
          buf.write_string(json_escape(status))
          buf.write_string("\"")
        }
        None => ()
      }
      buf.write_string("}")
    }
    buf.write_string("]}")
    println(buf.to_string())
  } else {
    for i in 0..<reports.length() {
      if i > 0 {
        println("")
      }
      print_verify_report(reports[i])
    }
  }
  if any_invalid {
    @env.exit(2)
  }
  if any_untrusted || any_revoked {
    @env.exit(3)
  }
}

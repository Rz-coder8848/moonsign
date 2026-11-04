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
  println("  moonsign info <in.pdf> [--json]")
  println("")
  println("Sign options:")
  println("  --out <path>      output PDF (default: <in>.signed.pdf)")
  println("  --chain <path>    extra certificates to embed")
  println("  --field <name>    signature field name (default: Signature1)")
  println("  --json            machine-readable summary")
  println("")
  println("Exit codes: 0 ok/valid, 2 invalid signature, 1 usage or I/O error")
}

///|
fn is_command(value : String) -> Bool {
  value == "sign" ||
  value == "verify" ||
  value == "info" ||
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
  mut field : String
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
    field: "Signature1",
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
      arg == "--field" {
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
fn sign_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let key_path = require(options.key, "private key (--key)")
  let cert_path = require(options.cert, "certificate (--cert)")
  let out_path = match options.out {
    Some(path) => path
    None => default_output(input)
  }
  let pdf_bytes = read_bytes(input)
  let key_text = read_text(key_path)
  let cert_text = read_text(cert_path)
  let key_blocks = @pem.parse_pem(key_text) catch {
    e => raise CliError::Failure("cannot parse key PEM: " + e.message())
  }
  let mut private_key : @pem.PrivateKey? = None
  for block in key_blocks {
    if block.label.contains("PRIVATE KEY") {
      let parsed = @pem.parse_private_key(block.der) catch {
        e => raise CliError::Failure("cannot parse private key: " + e.message())
      }
      private_key = Some(parsed)
      break
    }
  }
  let key = match private_key {
    Some(value) => value
    None => raise CliError::Failure("no private key block found in " + key_path)
  }
  let certs = @pem.parse_certificates(cert_text) catch {
    e => raise CliError::Failure("cannot parse certificate: " + e.message())
  }
  if certs.length() == 0 {
    raise CliError::Failure("no CERTIFICATE block found in " + cert_path)
  }
  let leaf = certs[0]
  let extra : Array[Bytes] = []
  for i in 1..<certs.length() {
    extra.push(certs[i].der)
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
  let signing_key = match key {
    @pem.PrivateKey::Rsa(modulus, private_exponent) =>
      @pades.SigningKey::Rsa(modulus, private_exponent)
    @pem.PrivateKey::EcdsaP256(scalar) => @pades.SigningKey::EcdsaP256(scalar)
  }
  let sign_options : @pades.SignOptions = {
    field_name: options.field,
    contents_chars: 16384,
    signing_time: None,
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
fn verify_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let cert_path = require(options.cert, "certificate (--cert)")
  let pdf_bytes = read_bytes(input)
  let cert_text = read_text(cert_path)
  let certs = @pem.parse_certificates(cert_text) catch {
    e => raise CliError::Failure("cannot parse certificate: " + e.message())
  }
  if certs.length() == 0 {
    raise CliError::Failure("no CERTIFICATE block found in " + cert_path)
  }
  let signatures = @pdf.signatures(pdf_bytes) catch {
    e => raise CliError::Failure(e.message())
  }
  if signatures.length() == 0 {
    raise CliError::Failure("no signature found in " + input)
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
  if !valid {
    @env.exit(2)
  }
}

///|
fn info_impl(args : Array[String]) -> Unit raise CliError {
  let options = parse_options(args)
  let input = require(options.input, "input PDF")
  let pdf_bytes = read_bytes(input)
  let signatures = @pdf.signatures(pdf_bytes) catch {
    e => raise CliError::Failure(e.message())
  }
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
      buf.write_string("}")
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
    }
  }
}

///|
fn run(command : String, args : Array[String]) -> Unit {
  let result : Result[Unit, String] = try {
    if command == "sign" {
      sign_impl(args)
    } else if command == "verify" {
      verify_impl(args)
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

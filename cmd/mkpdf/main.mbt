///|
fn parse_pages(text : String) -> Int32 {
  let mut value = 0
  for i in 0..<text.length() {
    match text.get_char(i) {
      Some(c) => {
        let digit = c.to_int() - 48
        if digit >= 0 && digit <= 9 {
          value = value * 10 + digit
        }
      }
      None => ()
    }
  }
  value
}

///|
fn main {
  let args = @env.args()
  let mut path = "blank.pdf"
  let mut with_field = false
  let mut pages = 0
  let mut encrypt : String? = None
  let mut rich = false
  let mut index = 1
  while index < args.length() {
    let arg = args[index]
    if arg == "--with-field" {
      with_field = true
      index = index + 1
    } else if arg == "--rich" {
      rich = true
      index = index + 1
    } else if arg == "--pages" && index + 1 < args.length() {
      pages = parse_pages(args[index + 1])
      index = index + 2
    } else if arg == "--encrypt" && index + 1 < args.length() {
      encrypt = Some(args[index + 1])
      index = index + 2
    } else {
      match arg.get_char(0) {
        Some(c) => if c != '-' { path = arg }
        None => ()
      }
      index = index + 1
    }
  }
  let base_bytes = if rich {
    @pdf.rich_pdf(if pages > 0 { pages } else { 3 })
  } else if pages > 0 {
    @pdf.paged_pdf(pages)
  } else {
    let document = @pdflite.pdf_minimum_valid_pdf() catch {
      _ => abort("failed to create a minimal PDF")
    }
    if with_field {
      @pdf.add_empty_signature_field(document, "Signature1") catch {
        _ => abort("failed to add the signature field")
      }
    }
    @pdflite.pdf_write_document(document) catch {
      _ => abort("failed to serialize the PDF")
    }
  }
  let bytes = match encrypt {
    Some(password) => {
      let document = @pdflite.pdf_read_document_from_bytes(base_bytes) catch {
        _ => abort("failed to read the generated PDF")
      }
      @pdflite.pdf_write_encrypted_128bit_document(
        document,
        @utf8.encode(password).clamped_view(),
        @utf8.encode(password).clamped_view(),
        [],
      ) catch {
        _ => abort("failed to encrypt the PDF")
      }
    }
    None => base_bytes
  }
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => abort("failed to write " + path)
  }
  println("wrote " + path)
}

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
  let mut index = 1
  while index < args.length() {
    let arg = args[index]
    if arg == "--with-field" {
      with_field = true
      index = index + 1
    } else if arg == "--pages" && index + 1 < args.length() {
      pages = parse_pages(args[index + 1])
      index = index + 2
    } else {
      match arg.get_char(0) {
        Some(c) => if c != '-' { path = arg }
        None => ()
      }
      index = index + 1
    }
  }
  let bytes = if pages > 0 {
    @pdf.paged_pdf(pages)
  } else {
    let document = @pdflite.pdf_minimum_valid_pdf() catch {
      _ => abort("failed to create a minimal PDF")
    }
    if with_field {
      // Add an empty signature field so other tools (for example pyHanko) can
      // fill it.
      @pdf.add_empty_signature_field(document, "Signature1") catch {
        _ => abort("failed to add the signature field")
      }
    }
    @pdflite.pdf_write_document(document) catch {
      _ => abort("failed to serialize the PDF")
    }
  }
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => abort("failed to write " + path)
  }
  println("wrote " + path)
}

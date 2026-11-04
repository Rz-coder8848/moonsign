///|
fn main {
  let args = @env.args()
  let mut path = "blank.pdf"
  let mut with_field = false
  for arg in args {
    if arg == "--with-field" {
      with_field = true
    } else {
      match arg.get_char(0) {
        Some(c) => if c != '-' { path = arg }
        None => ()
      }
    }
  }
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
  let bytes = @pdflite.pdf_write_document(document) catch {
    _ => abort("failed to serialize the PDF")
  }
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => abort("failed to write " + path)
  }
  println("wrote " + path)
}

///|
fn nm(value : String) -> @pdfcore.PdfName {
  @pdfcore.pdf_name_of_bytes(@utf8.encode(value))
}

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
  let doc = @pdflite.pdf_read_document_from_bytes(bytes) catch {
    _ => abort("parse")
  }
  let catalog = doc.catalog() catch { _ => abort("catalog") }
  let updated = catalog.add_dict_entry(
    nm("Foo"),
    @pdfsyntax.PdfObject::PdfInteger(7),
  ) catch {
    _ => abort("add")
  }
  doc.add_object_given_number(doc.root(), updated)
  let out = @pdflite.pdf_write_document_incremental_update(bytes, doc) catch {
    _ => abort("incremental")
  }
  let appended = Array::make(out.length() - bytes.length(), b'\x00')
  for i in 0..<appended.length() {
    appended[i] = out[bytes.length() + i]
  }
  println("BASE:" + bytes.length().to_string())
  println("APPEND:" + hex_of(Bytes::from_array(appended[:])))
}

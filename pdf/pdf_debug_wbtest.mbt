///|
test "prepared document exposes a signature field" {
  let base = @pdflite.pdf_minimum_valid_pdf() catch { _ => fail("minimal pdf") }
  let bytes = @pdflite.pdf_write_document(base) catch { _ => fail("serialize") }
  let prepared = prepare(bytes, "Signature1", 4096) catch {
    _ => fail("prepare")
  }
  let text = text_of_bytes(prepared)
  inspect(text.contains("/AcroForm"), content="true")
  inspect(text.contains("/Sig"), content="true")
  let doc = @pdflite.pdf_read_document_from_bytes(prepared) catch {
    _ => fail("reparse")
  }
  let catalog = doc.catalog() catch { _ => fail("catalog") }
  let keys = match catalog.dictionary_view() {
    Some(entries) => {
      let buf = StringBuilder()
      for entry in entries {
        buf.write_string(text_of_name(entry.0))
        buf.write_string(",")
      }
      buf.to_string()
    }
    None => "<not-dict>"
  }
  inspect(keys, content="AcroForm,Pages,Type,")
  let cat_type = match catalog.lookup_immediate(name("Type")) {
    Some(@pdfsyntax.PdfObject::PdfNameObject(value)) => text_of_name(value)
    _ => "<none>"
  }
  inspect(cat_type, content="Catalog")
  inspect(doc.root().to_string(), content="3")
  let acro = match catalog.lookup_immediate(name("AcroForm")) {
    Some(value) => resolve(doc, value)
    None => fail("catalog has no AcroForm")
  }
  let fields = match acro.lookup_immediate(name("Fields")) {
    Some(value) => resolve(doc, value)
    None => fail("AcroForm has no Fields")
  }
  let count = match fields {
    @pdfsyntax.PdfObject::PdfArray(values) => values.length()
    _ => -1
  }
  inspect(count, content="1")
  let extracted = signatures(prepared) catch { _ => fail("signatures") }
  inspect(extracted.length(), content="1")
}

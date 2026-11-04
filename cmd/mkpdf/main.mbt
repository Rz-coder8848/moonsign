///|
fn nm(value : String) -> @pdfcore.PdfName {
  @pdfcore.pdf_name_of_bytes(@utf8.encode("/" + value))
}

///|
fn main {
  let args = @env.args()
  let mut path = "blank.pdf"
  if args.length() > 1 {
    path = args[args.length() - 1]
  }
  let document = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => abort("failed to create a minimal PDF")
  }
  // Add an empty AcroForm so other tools (for example pyHanko) can add fields.
  let catalog = document.catalog() catch {
    _ => abort("failed to read the catalog")
  }
  let acroform = @pdfsyntax.PdfObject::PdfDictionary([
    (nm("Fields"), @pdfsyntax.PdfObject::PdfArray([])),
    (nm("SigFlags"), @pdfsyntax.PdfObject::PdfInteger(3)),
  ])
  let acroform_number = document.add_object(acroform)
  let updated_catalog = catalog.add_dict_entry(
    nm("AcroForm"),
    @pdfsyntax.PdfObject::PdfIndirect(acroform_number),
  ) catch {
    _ => abort("failed to attach the AcroForm")
  }
  document.add_object_given_number(document.root(), updated_catalog)
  let bytes = @pdflite.pdf_write_document(document) catch {
    _ => abort("failed to serialize the PDF")
  }
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => abort("failed to write " + path)
  }
  println("wrote " + path)
}

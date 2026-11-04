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
  let bytes = @pdflite.pdf_write_document(document) catch {
    _ => abort("failed to serialize the PDF")
  }
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => abort("failed to write " + path)
  }
  println("wrote " + path)
}

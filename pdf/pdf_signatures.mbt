///|
/// A signature field extracted from a PDF.
pub(all) struct PdfSignature {
  field_name : String
  subfilter : String
  byte_range : Array[Int32]
  contents : Bytes
}

///|
fn text_of_bytes(bytes : Bytes) -> String {
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    buf.write_char(bytes[i].to_char())
  }
  buf.to_string()
}

///|
fn text_of_name(value : @pdfcore.PdfName) -> String {
  let bytes = value.bytes()
  let start = if bytes.length() > 0 && bytes[0].to_int() == 47 { 1 } else { 0 }
  let length = bytes.length() - start
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = bytes[start + i]
  }
  text_of_bytes(Bytes::from_array(out[:]))
}

///|
fn integer_of(object : @pdfsyntax.PdfObject) -> Int32? {
  match object {
    @pdfsyntax.PdfObject::PdfInteger(value) => Some(value)
    _ => None
  }
}

///|
/// Extract all `/FT /Sig` signature fields, including their byte ranges and
/// raw `/Contents` bytes.
///
/// The `/Contents` value is returned decoded: for hex strings the bytes are the
/// decoded octets, not the hex text.
pub fn signatures(pdf : Bytes) -> Array[PdfSignature] raise PdfSignError {
  let doc = @pdflite.pdf_read_document_from_bytes(pdf) catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  let out : Array[PdfSignature] = []
  let catalog = doc.catalog() catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  let acroform = match catalog.lookup_immediate(name("AcroForm")) {
    Some(value) => resolve(doc, value)
    None => return out
  }
  let fields_object = match acroform.lookup_immediate(name("Fields")) {
    Some(value) => resolve(doc, value)
    None => return out
  }
  let fields = match fields_object {
    @pdfsyntax.PdfObject::PdfArray(values) => values
    _ => return out
  }
  for field_ref in fields {
    let field = resolve(doc, field_ref)
    let field_type = match field.lookup_immediate(name("FT")) {
      Some(@pdfsyntax.PdfObject::PdfNameObject(value)) => text_of_name(value)
      _ => continue
    }
    if field_type != "Sig" {
      continue
    }
    let field_name = match field.lookup_immediate(name("T")) {
      Some(@pdfsyntax.PdfObject::PdfString(value)) => text_of_bytes(value)
      Some(@pdfsyntax.PdfObject::PdfNameObject(value)) => text_of_name(value)
      _ => ""
    }
    let signature = match field.lookup_immediate(name("V")) {
      Some(value) => resolve(doc, value)
      None => continue
    }
    let subfilter = match signature.lookup_immediate(name("SubFilter")) {
      Some(@pdfsyntax.PdfObject::PdfNameObject(value)) => text_of_name(value)
      _ => ""
    }
    let byte_range_object = match
      signature.lookup_immediate(name("ByteRange")) {
      Some(value) => resolve(doc, value)
      None => continue
    }
    let byte_range = match byte_range_object {
      @pdfsyntax.PdfObject::PdfArray(values) => {
        let numbers : Array[Int32] = []
        for value in values {
          match integer_of(value) {
            Some(number) => numbers.push(number)
            None => ()
          }
        }
        numbers
      }
      _ => continue
    }
    let contents = match signature.lookup_immediate(name("Contents")) {
      Some(@pdfsyntax.PdfObject::PdfString(value)) => value
      _ => continue
    }
    out.push({ field_name, subfilter, byte_range, contents, })
  }
  out
}

///|
/// Slice the two byte ranges declared by a signature.
///
/// Returns `None` when the ranges are malformed or out of bounds.
pub fn bytes_for_signature(
  pdf : Bytes,
  signature : PdfSignature,
) -> Array[Bytes]? {
  let ranges = signature.byte_range
  if ranges.length() != 4 {
    return None
  }
  let first_start = ranges[0]
  let first_length = ranges[1]
  let second_start = ranges[2]
  let second_length = ranges[3]
  if first_start < 0 ||
    first_length < 0 ||
    second_start < 0 ||
    second_length < 0 {
    return None
  }
  if first_start + first_length > pdf.length() ||
    second_start + second_length > pdf.length() {
    return None
  }
  let parts : Array[Bytes] = []
  let first = Array::make(first_length, b'\x00')
  for i in 0..<first_length {
    first[i] = pdf[first_start + i]
  }
  parts.push(Bytes::from_array(first[:]))
  let second = Array::make(second_length, b'\x00')
  for i in 0..<second_length {
    second[i] = pdf[second_start + i]
  }
  parts.push(Bytes::from_array(second[:]))
  Some(parts)
}

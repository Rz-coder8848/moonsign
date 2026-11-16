///|
fn dss_stream(der : Bytes) -> @pdfsyntax.PdfObject {
  let entries : Array[(@pdfcore.PdfName, @pdfsyntax.PdfObject)] = [
    (name("Type"), name_object("EmbeddedFile")),
    (name("Length"), int_object(der.length())),
  ]
  @pdfsyntax.pdf_stream(dict(entries), @pdfsyntax.PdfStreamData::StreamGot(der))
}

///|
fn add_stream_objects(
  doc : @pdflite.PdfDocument,
  items : Array[Bytes],
) -> Array[@pdfsyntax.PdfObject] {
  let refs : Array[@pdfsyntax.PdfObject] = []
  for item in items {
    let number = doc.add_object(dss_stream(item))
    refs.push(indirect(number))
  }
  refs
}

///|
/// Add a Document Security Store (DSS) with certificates, CRLs and OCSP
/// responses, appended as an incremental update so existing signatures stay
/// valid.
pub fn add_dss(
  pdf : Bytes,
  certificates : Array[Bytes],
  crls : Array[Bytes],
  ocsps : Array[Bytes],
) -> Bytes raise PdfSignError {
  let doc = @pdflite.pdf_read_document_from_bytes(pdf) catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  if doc.is_encrypted() {
    raise PdfSignError::Encrypted
  }
  let cert_refs = add_stream_objects(doc, certificates)
  let crl_refs = add_stream_objects(doc, crls)
  let ocsp_refs = add_stream_objects(doc, ocsps)
  let entries : Array[(@pdfcore.PdfName, @pdfsyntax.PdfObject)] = []
  if cert_refs.length() > 0 {
    entries.push((name("Certs"), array_object(cert_refs)))
  }
  if crl_refs.length() > 0 {
    entries.push((name("CRLs"), array_object(crl_refs)))
  }
  if ocsp_refs.length() > 0 {
    entries.push((name("OCSPs"), array_object(ocsp_refs)))
  }
  if entries.length() == 0 {
    return pdf
  }
  let dss_number = doc.add_object(dict(entries))
  let catalog = doc.catalog() catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  let updated = set_entry(catalog, name("DSS"), indirect(dss_number))
  doc.add_object_given_number(doc.root(), updated)
  @pdflite.pdf_write_document_incremental_update_with_xref_stream(pdf, doc) catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
}

///|
/// Validation material embedded in a PDF's Document Security Store.
pub(all) struct DssMaterial {
  certificates : Array[Bytes]
  crls : Array[Bytes]
  ocsps : Array[Bytes]
}

///|
fn dss_entries(
  doc : @pdflite.PdfDocument,
  dss : @pdfsyntax.PdfObject,
  key : String,
) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let array = match dss.lookup_immediate(name(key)) {
    Some(value) => resolve(doc, value)
    None => return out
  }
  let items = match array {
    @pdfsyntax.PdfObject::PdfArray(values) => values
    _ => return out
  }
  for item in items {
    let object = resolve(doc, item)
    match object {
      @pdfsyntax.PdfObject::PdfStreamObject(stream) => {
        let bytes = @pdfsyntax.pdf_stream_data_bytes(stream.data) catch {
          _ => continue
        }
        out.push(bytes)
      }
      _ => ()
    }
  }
  out
}

///|
/// Read certificates, CRLs and OCSP responses from a PDF's DSS.
pub fn dss_material(pdf : Bytes) -> DssMaterial raise PdfSignError {
  let doc = @pdflite.pdf_read_document_from_bytes(pdf) catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  let empty : DssMaterial = { certificates: [], crls: [], ocsps: [], }
  if doc.is_encrypted() {
    return empty
  }
  let catalog = doc.catalog() catch { _ => return empty }
  let dss = match catalog.lookup_immediate(name("DSS")) {
    Some(value) => resolve(doc, value)
    None => return empty
  }
  {
    certificates: dss_entries(doc, dss, "Certs"),
    crls: dss_entries(doc, dss, "CRLs"),
    ocsps: dss_entries(doc, dss, "OCSPs"),
  }
}

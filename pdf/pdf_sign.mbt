///|
/// Optional visible signature appearance drawn on the page.
pub(all) struct SignatureAppearance {
  x1 : Int32
  y1 : Int32
  x2 : Int32
  y2 : Int32
  /// Text lines drawn inside the box (ASCII; other characters become `?`).
  lines : Array[String]
}

///|
/// Errors raised while adding a PDF signature placeholder.
pub(all) suberror PdfSignError {
  PdfFailure(String)
  Encrypted
  NoPages
  Malformed(String)
  PlaceholderMissing
  PlaceholderTooSmall(Int32, Int32)
  OffsetTooLarge(Int32)
}

///|
/// Where the signature placeholder lives in the prepared PDF.
pub(all) struct SignatureSlot {
  /// Byte offset of the `<` that opens the `/Contents` hex string.
  open_pos : Int32
  /// Byte offset of the `>` that closes the `/Contents` hex string.
  close_pos : Int32
  /// Byte offset of the `[` that opens `/ByteRange`.
  byte_range_pos : Int32
  /// Number of hex characters available inside `<...>`.
  capacity : Int32
}

///|
fn name(value : String) -> @pdfcore.PdfName {
  @pdfcore.pdf_name_of_bytes(@utf8.encode("/" + value))
}

///|
fn name_object(value : String) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfNameObject(name(value))
}

///|
fn dict(
  entries : Array[(@pdfcore.PdfName, @pdfsyntax.PdfObject)],
) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfDictionary(entries)
}

///|
fn int_object(value : Int32) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfInteger(value)
}

///|
fn array_object(values : Array[@pdfsyntax.PdfObject]) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfArray(values)
}

///|
fn indirect(number : Int32) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfIndirect(number)
}

///|
fn string_object(value : Bytes) -> @pdfsyntax.PdfObject {
  @pdfsyntax.PdfObject::PdfString(value)
}

///|
fn set_entry(
  object : @pdfsyntax.PdfObject,
  key : @pdfcore.PdfName,
  value : @pdfsyntax.PdfObject,
) -> @pdfsyntax.PdfObject raise PdfSignError {
  let present = match object.lookup_immediate(key) {
    Some(_) => true
    None => false
  }
  if present {
    object.replace_dict_entry(key, value) catch {
      e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
    }
  } else {
    object.add_dict_entry(key, value) catch {
      e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
    }
  }
}

///|
fn resolve(
  doc : @pdflite.PdfDocument,
  object : @pdfsyntax.PdfObject,
) -> @pdfsyntax.PdfObject {
  doc.direct(object)
}

///|
fn append_field(
  doc : @pdflite.PdfDocument,
  acroform : @pdfsyntax.PdfObject,
  field_number : Int32,
) -> @pdfsyntax.PdfObject raise PdfSignError {
  let fields = match acroform.lookup_immediate(name("Fields")) {
    Some(value) => resolve(doc, value)
    None => array_object([])
  }
  let updated_fields = match fields {
    @pdfsyntax.PdfObject::PdfArray(values) => {
      let copy : Array[@pdfsyntax.PdfObject] = []
      for value in values {
        copy.push(value)
      }
      copy.push(indirect(field_number))
      array_object(copy)
    }
    _ => array_object([indirect(field_number)])
  }
  let with_fields = set_entry(acroform, name("Fields"), updated_fields)
  set_entry(with_fields, name("SigFlags"), int_object(3))
}

///|
fn ensure_acroform(
  doc : @pdflite.PdfDocument,
  field_number : Int32,
) -> Unit raise PdfSignError {
  let catalog = doc.catalog() catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  let root_number = doc.root()
  match catalog.lookup_immediate(name("AcroForm")) {
    Some(existing) =>
      match resolve(doc, existing) {
        @pdfsyntax.PdfObject::PdfDictionary(_) =>
          match existing {
            @pdfsyntax.PdfObject::PdfIndirect(number) => {
              let acroform = doc.lookup_object_or_null(number)
              let updated = append_field(doc, acroform, field_number)
              doc.add_object_given_number(number, updated)
            }
            _ => {
              let updated = append_field(doc, existing, field_number)
              let new_catalog = set_entry(catalog, name("AcroForm"), updated)
              doc.add_object_given_number(root_number, new_catalog)
            }
          }
        _ => raise PdfSignError::Malformed("AcroForm is not a dictionary")
      }
    None => {
      let acroform = dict([
        (name("Fields"), array_object([indirect(field_number)])),
        (name("SigFlags"), int_object(3)),
      ])
      let acroform_number = doc.add_object(acroform)
      let new_catalog = set_entry(
        catalog,
        name("AcroForm"),
        indirect(acroform_number),
      )
      doc.add_object_given_number(root_number, new_catalog)
    }
  }
}

///|
fn append_annotation(
  doc : @pdflite.PdfDocument,
  page_number : Int32,
  field_number : Int32,
) -> Unit raise PdfSignError {
  let page = doc.lookup_object_or_null(page_number)
  let annots = match page.lookup_immediate(name("Annots")) {
    Some(value) => resolve(doc, value)
    None => array_object([])
  }
  let updated = match annots {
    @pdfsyntax.PdfObject::PdfArray(values) => {
      let copy : Array[@pdfsyntax.PdfObject] = []
      for value in values {
        copy.push(value)
      }
      copy.push(indirect(field_number))
      array_object(copy)
    }
    _ => array_object([indirect(field_number)])
  }
  let new_page = set_entry(page, name("Annots"), updated)
  doc.add_object_given_number(page_number, new_page)
}

///|
/// Add an invisible signature field with a fixed-size `/Contents` placeholder
/// and a fixed-width `/ByteRange` placeholder, then append an incremental
/// revision.
///
/// `contents_chars` is the number of hex characters reserved for the CMS
/// signature (must be even). The returned PDF still has no signature value;
/// call `locate`, hash the declared ranges, build the CMS, then `embed`.

///|
fn pdf_floor_div64(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  let r = a % b
  if r != 0 && (r < 0) != (b < 0) {
    q - 1
  } else {
    q
  }
}

///|
fn pdf_civil_from_days(days : Int32) -> (Int32, Int32, Int32) {
  let z = days + 719468
  let era = (if z >= 0 { z } else { z - 146096 }) / 146097
  let doe = z - era * 146097
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let y = yoe + era * 400
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp = (5 * doy + 2) / 153
  let d = doy - (153 * mp + 2) / 5 + 1
  let m = mp + (if mp < 10 { 3 } else { -9 })
  let year = y + (if m <= 2 { 1 } else { 0 })
  (year, m, d)
}

///|
fn pdf_pad2(value : Int32) -> String {
  if value < 10 {
    "0" + value.to_string()
  } else {
    value.to_string()
  }
}

///|
fn pdf_pad4(value : Int32) -> String {
  if value < 10 {
    "000" + value.to_string()
  } else if value < 100 {
    "00" + value.to_string()
  } else if value < 1000 {
    "0" + value.to_string()
  } else {
    value.to_string()
  }
}

///|
/// Format a Unix timestamp as a PDF date string (`D:YYYYMMDDHHmmSSZ`).
pub fn pdf_date_string(unix : Int64) -> String {
  let days64 = pdf_floor_div64(unix, Int64::from_int(86400))
  let seconds = unix - days64 * Int64::from_int(86400)
  let days = days64.to_int()
  let (year, month, day) = pdf_civil_from_days(days)
  let hour = (seconds / Int64::from_int(3600)).to_int()
  let minute = (seconds % Int64::from_int(3600) / Int64::from_int(60)).to_int()
  let second = (seconds % Int64::from_int(60)).to_int()
  "D:" +
  pdf_pad4(year) +
  pdf_pad2(month) +
  pdf_pad2(day) +
  pdf_pad2(hour) +
  pdf_pad2(minute) +
  pdf_pad2(second) +
  "Z"
}

///|
/// Add an invisible signature field with a fixed-size `/Contents` placeholder
/// and a fixed-width `/ByteRange` placeholder, then append a new revision.
///
/// `contents_chars` is the number of hex characters reserved for the CMS
/// signature (must be even). Optional metadata is written into the signature
/// dictionary (`/M`, `/Reason`, `/Location`, `/ContactInfo`).

///|
fn pdf_escape(text : String) -> String {
  let buf = StringBuilder()
  for i in 0..<text.length() {
    let c = text.get_char(i).unwrap()
    let code = c.to_int()
    if c == '(' || c == ')' || c == '\\' {
      buf.write_char('\\')
    }
    if code >= 32 && code < 127 {
      buf.write_char(c)
    } else {
      buf.write_char('?')
    }
  }
  buf.to_string()
}

///|
fn appearance_content(lines : Array[String]) -> String {
  let buf = StringBuilder()
  buf.write_string("BT /Helvetica 9 Tf 4 4 Td ")
  for i in 0..<lines.length() {
    if i > 0 {
      buf.write_string("0 -12 Td ")
    }
    buf.write_string("(" + pdf_escape(lines[i]) + ") Tj ")
  }
  buf.write_string("ET")
  buf.to_string()
}

///|
pub fn prepare(
  pdf : Bytes,
  field_name : String,
  contents_chars : Int32,
  reason? : String,
  location? : String,
  contact? : String,
  signing_time? : Int64,
  appearance? : SignatureAppearance,
  incremental? : Bool,
) -> Bytes raise PdfSignError {
  if contents_chars < 64 || contents_chars % 2 != 0 {
    raise PdfSignError::Malformed("contents_chars must be an even number >= 64")
  }
  let doc = @pdflite.pdf_read_document_from_bytes(pdf) catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  if doc.is_encrypted() {
    raise PdfSignError::Encrypted
  }
  let pages = doc.page_reference_numbers() catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  if pages.length() == 0 {
    raise PdfSignError::NoPages
  }
  let page_number = pages[0]
  let placeholder = Array::make(contents_chars, b'0')
  let entries : Array[(@pdfcore.PdfName, @pdfsyntax.PdfObject)] = [
    (name("Type"), name_object("Sig")),
    (name("Filter"), name_object("Adobe.PPKLite")),
    (name("SubFilter"), name_object("ETSI.CAdES.detached")),
    (
      name("ByteRange"),
      array_object([
        int_object(1000000000),
        int_object(1000000000),
        int_object(1000000000),
        int_object(1000000000),
      ]),
    ),
    (name("Contents"), string_object(Bytes::from_array(placeholder[:]))),
  ]
  match signing_time {
    Some(value) =>
      entries.push(
        (name("M"), string_object(@utf8.encode(pdf_date_string(value)))),
      )
    None => ()
  }
  match reason {
    Some(value) =>
      entries.push((name("Reason"), string_object(@utf8.encode(value))))
    None => ()
  }
  match location {
    Some(value) =>
      entries.push((name("Location"), string_object(@utf8.encode(value))))
    None => ()
  }
  match contact {
    Some(value) =>
      entries.push((name("ContactInfo"), string_object(@utf8.encode(value))))
    None => ()
  }
  let signature_dictionary = dict(entries)
  let signature_number = doc.add_object(signature_dictionary)
  let rect_values = match appearance {
    Some(spec) => [spec.x1, spec.y1, spec.x2, spec.y2]
    None => [0, 0, 0, 0]
  }
  let field_entries : Array[(@pdfcore.PdfName, @pdfsyntax.PdfObject)] = [
    (name("Type"), name_object("Annot")),
    (name("Subtype"), name_object("Widget")),
    (name("FT"), name_object("Sig")),
    (name("T"), string_object(@utf8.encode(field_name))),
    (name("V"), indirect(signature_number)),
    (name("F"), int_object(4)),
    (name("P"), indirect(page_number)),
    (
      name("Rect"),
      array_object([
        int_object(rect_values[0]),
        int_object(rect_values[1]),
        int_object(rect_values[2]),
        int_object(rect_values[3]),
      ]),
    ),
  ]
  match appearance {
    Some(spec) => {
      let width = if spec.x2 > spec.x1 { spec.x2 - spec.x1 } else { 1 }
      let height = if spec.y2 > spec.y1 { spec.y2 - spec.y1 } else { 1 }
      let font_number = doc.add_object(
        dict([
          (name("Type"), name_object("Font")),
          (name("Subtype"), name_object("Type1")),
          (name("BaseFont"), name_object("Helvetica")),
        ]),
      )
      let resources = dict([
        (name("Font"), dict([(name("Helvetica"), indirect(font_number))])),
      ])
      let appearance_dictionary = dict([
        (name("Type"), name_object("XObject")),
        (name("Subtype"), name_object("Form")),
        (
          name("BBox"),
          array_object([
            int_object(0),
            int_object(0),
            int_object(width),
            int_object(height),
          ]),
        ),
        (name("Resources"), resources),
      ])
      let content = appearance_content(spec.lines)
      let appearance_object = @pdfsyntax.pdf_stream(
        appearance_dictionary,
        @pdfsyntax.PdfStreamData::StreamGot(@utf8.encode(content)),
      )
      let appearance_number = doc.add_object(appearance_object)
      field_entries.push(
        (name("AP"), dict([(name("N"), indirect(appearance_number))])),
      )
    }
    None => ()
  }
  let field = dict(field_entries)
  let field_number = doc.add_object(field)
  append_annotation(doc, page_number, field_number)
  ensure_acroform(doc, field_number)
  if incremental.unwrap_or(false) {
    @pdflite.pdf_write_document_incremental_update_with_xref_stream(pdf, doc) catch {
      e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
    }
  } else {
    @pdflite.pdf_write_document(doc) catch {
      e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
    }
  }
}

///|
fn find_bytes(haystack : Bytes, needle : Bytes, from : Int32) -> Int32? {
  let n = needle.length()
  if n == 0 || haystack.length() < n {
    return None
  }
  let mut i = from
  while i + n <= haystack.length() {
    let mut j = 0
    while j < n && haystack[i + j].to_int() == needle[j].to_int() {
      j = j + 1
    }
    if j == n {
      return Some(i)
    }
    i = i + 1
  }
  None
}

///|
/// Locate the `/Contents` and `/ByteRange` placeholders.
pub fn locate(
  pdf : Bytes,
  contents_chars : Int32,
) -> SignatureSlot raise PdfSignError {
  let zeros = Array::make(contents_chars, b'0')
  let zero_bytes = Bytes::from_array(zeros[:])
  let content_pos = match find_bytes(pdf, zero_bytes, 0) {
    Some(pos) => pos
    None => raise PdfSignError::PlaceholderMissing
  }
  if content_pos == 0 {
    raise PdfSignError::PlaceholderMissing
  }
  let open_pos = content_pos - 1
  if pdf[open_pos].to_int() != 40 {
    raise PdfSignError::PlaceholderMissing
  }
  let close_pos = content_pos + contents_chars
  if close_pos >= pdf.length() || pdf[close_pos].to_int() != 41 {
    raise PdfSignError::PlaceholderMissing
  }
  let marker = "1000000000 1000000000 1000000000 1000000000".to_string()
  let marker_bytes = Array::make(marker.length(), b'0')
  for i in 0..<marker.length() {
    marker_bytes[i] = marker.get_char(i).unwrap().to_int().to_byte()
  }
  let marker_pos = match
    find_bytes(pdf, Bytes::from_array(marker_bytes[:]), 0) {
    Some(pos) => pos
    None => raise PdfSignError::PlaceholderMissing
  }
  if marker_pos == 0 || pdf[marker_pos - 1].to_int() != 91 {
    raise PdfSignError::PlaceholderMissing
  }
  {
    open_pos,
    close_pos,
    byte_range_pos: marker_pos - 1,
    capacity: contents_chars,
  }
}

///|
fn pad10(value : Int32) -> String {
  let text = value.to_string()
  if text.length() >= 10 {
    text
  } else {
    let zeros = StringBuilder()
    for _ in 0..<(10 - text.length()) {
      zeros.write_string("0")
    }
    zeros.to_string() + text
  }
}

///|
fn hex_digit(value : Int32) -> Char {
  if value < 10 {
    (48 + value).unsafe_to_char()
  } else {
    (87 + value).unsafe_to_char()
  }
}

///|
/// Size of the byte ranges that a signature covers, for a prepared PDF.
pub fn signed_ranges(pdf : Bytes, slot : SignatureSlot) -> Array[Bytes] {
  let parts : Array[Bytes] = []
  let first = Array::make(slot.open_pos, b'\x00')
  for i in 0..<slot.open_pos {
    first[i] = pdf[i]
  }
  parts.push(Bytes::from_array(first[:]))
  let second_start = slot.close_pos + 1
  let second_length = pdf.length() - second_start
  let second = Array::make(second_length, b'\x00')
  for i in 0..<second_length {
    second[i] = pdf[second_start + i]
  }
  parts.push(Bytes::from_array(second[:]))
  parts
}

///|
/// Patch `/ByteRange` with the real offsets and switch the `/Contents`
/// placeholder to a hex string.
///
/// The returned bytes are what the signature digest is computed over; call
/// `embed` afterwards to write the CMS into the reserved space.
pub fn seal_layout(
  pdf : Bytes,
  contents_chars : Int32,
) -> (Bytes, SignatureSlot) raise PdfSignError {
  let slot = locate(pdf, contents_chars)
  let total = pdf.length()
  let second_start = slot.close_pos + 1
  let range_end = total - second_start
  let byte_range = "[" +
    pad10(0) +
    " " +
    pad10(slot.open_pos) +
    " " +
    pad10(second_start) +
    " " +
    pad10(range_end) +
    "]"
  if byte_range.length() != 45 {
    raise PdfSignError::Malformed("internal ByteRange width error")
  }
  let out = Array::make(total, b'\x00')
  for i in 0..<total {
    out[i] = pdf[i]
  }
  for i in 0..<45 {
    out[slot.byte_range_pos + i] = byte_range
      .get_char(i)
      .unwrap()
      .to_int()
      .to_byte()
  }
  out[slot.open_pos] = b'<'
  out[slot.close_pos] = b'>'
  (Bytes::from_array(out[:]), slot)
}

///|
/// Write a DER-encoded CMS signature into a sealed placeholder.
///
/// The CMS is hex-encoded and zero-padded to the reserved capacity. The
/// `/ByteRange` numbers must already be final (see `seal_layout`).
pub fn embed(
  pdf : Bytes,
  slot : SignatureSlot,
  cms_der : Bytes,
) -> Bytes raise PdfSignError {
  if pdf[slot.open_pos].to_int() != 60 || pdf[slot.close_pos].to_int() != 62 {
    raise PdfSignError::Malformed("PDF signature layout is not sealed")
  }
  let hex_chars = cms_der.length() * 2
  if hex_chars > slot.capacity {
    raise PdfSignError::PlaceholderTooSmall(slot.capacity, hex_chars)
  }
  let total = pdf.length()
  let out = Array::make(total, b'\x00')
  for i in 0..<total {
    out[i] = pdf[i]
  }
  for i in 0..<hex_chars {
    let byte = cms_der[i / 2].to_int()
    let digit = if i % 2 == 0 { byte / 16 } else { byte % 16 }
    out[slot.open_pos + 1 + i] = hex_digit(digit).to_int().to_byte()
  }
  for i in hex_chars..<slot.capacity {
    out[slot.open_pos + 1 + i] = b'0'
  }
  Bytes::from_array(out[:])
}

///|
/// Human-readable description of a PDF signing error.
pub fn PdfSignError::message(self : PdfSignError) -> String {
  match self {
    PdfFailure(detail) => "PDF error: \{detail}"
    Encrypted => "encrypted PDFs are not supported"
    NoPages => "PDF has no pages"
    Malformed(detail) => "malformed PDF: \{detail}"
    PlaceholderMissing => "signature placeholder not found"
    PlaceholderTooSmall(capacity, needed) =>
      "signature placeholder too small: \{capacity} hex chars available, \{needed} needed"
    OffsetTooLarge(value) => "byte offset too large: \{value}"
  }
}

///|
/// Add an empty signature field (no signature value) to a document.
///
/// This is useful for interoperability tests: other signers can then fill the
/// field instead of creating one themselves.
pub fn add_empty_signature_field(
  doc : @pdflite.PdfDocument,
  field_name : String,
) -> Unit raise PdfSignError {
  let pages = doc.page_reference_numbers() catch {
    e => raise PdfSignError::PdfFailure(@pdfcore.pdf_error_summary(e))
  }
  if pages.length() == 0 {
    raise PdfSignError::NoPages
  }
  let page_number = pages[0]
  let field = dict([
    (name("Type"), name_object("Annot")),
    (name("Subtype"), name_object("Widget")),
    (name("FT"), name_object("Sig")),
    (name("T"), string_object(@utf8.encode(field_name))),
    (name("F"), int_object(4)),
    (name("P"), indirect(page_number)),
    (
      name("Rect"),
      array_object([int_object(0), int_object(0), int_object(0), int_object(0)]),
    ),
  ])
  let field_number = doc.add_object(field)
  append_annotation(doc, page_number, field_number)
  ensure_acroform(doc, field_number)
}

///|
fn is_pdf_whitespace(value : Byte) -> Bool {
  let code = value.to_int()
  code == 32 || code == 9 || code == 10 || code == 13
}

///|
/// Replace the hex `/Contents` of an existing signature in place.
///
/// The new CMS must fit in the reserved capacity; `/ByteRange` is not changed,
/// so the original signature remains valid when only unsigned attributes are
/// added.
pub fn replace_contents(
  pdf : Bytes,
  cms_der : Bytes,
) -> Bytes raise PdfSignError {
  let key = @utf8.encode("/Contents")
  let key_pos = match find_bytes(pdf, key, 0) {
    Some(pos) => pos
    None => raise PdfSignError::PlaceholderMissing
  }
  let mut pos = key_pos + key.length()
  while pos < pdf.length() && is_pdf_whitespace(pdf[pos]) {
    pos = pos + 1
  }
  if pos >= pdf.length() || pdf[pos].to_int() != 60 {
    raise PdfSignError::PlaceholderMissing
  }
  let open_pos = pos
  let mut close = open_pos + 1
  while close < pdf.length() && pdf[close].to_int() != 62 {
    close = close + 1
  }
  if close >= pdf.length() {
    raise PdfSignError::PlaceholderMissing
  }
  let capacity = close - open_pos - 1
  let hex_chars = cms_der.length() * 2
  if hex_chars > capacity {
    raise PdfSignError::PlaceholderTooSmall(capacity, hex_chars)
  }
  let out = Array::make(pdf.length(), b'\x00')
  for i in 0..<pdf.length() {
    out[i] = pdf[i]
  }
  for i in 0..<hex_chars {
    let byte = cms_der[i / 2].to_int()
    let digit = if i % 2 == 0 { byte / 16 } else { byte % 16 }
    out[open_pos + 1 + i] = hex_digit(digit).to_int().to_byte()
  }
  for i in hex_chars..<capacity {
    out[open_pos + 1 + i] = b'0'
  }
  Bytes::from_array(out[:])
}

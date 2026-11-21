///|
fn pad10_offset(value : Int32) -> String {
  let text = value.to_string()
  if text.length() >= 10 {
    text
  } else {
    let buf = StringBuilder()
    for _ in 0..<(10 - text.length()) {
      buf.write_string("0")
    }
    buf.to_string() + text
  }
}

///|
/// Build a small multi-page PDF with text content and a link annotation on each
/// page. Useful as a "realistic" compatibility fixture.
pub fn rich_pdf(pages : Int32) -> Bytes {
  let count = if pages < 1 { 1 } else { pages }
  let parts : Array[String] = []
  let offsets : Array[Int32] = []
  let mut total = 0
  let header = "%PDF-1.7\n"
  parts.push(header)
  total = total + header.length()
  let catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
  offsets.push(total)
  parts.push(catalog)
  total = total + catalog.length()
  let kids = StringBuilder()
  for i in 0..<count {
    if i > 0 {
      kids.write_string(" ")
    }
    kids.write_string((4 + i * 3).to_string() + " 0 R")
  }
  let page_tree = "2 0 obj\n<< /Type /Pages /Kids [" +
    kids.to_string() +
    "] /Count " +
    count.to_string() +
    " >>\nendobj\n"
  offsets.push(total)
  parts.push(page_tree)
  total = total + page_tree.length()
  let font = "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
  offsets.push(total)
  parts.push(font)
  total = total + font.length()
  for i in 0..<count {
    let page_number = 4 + i * 3
    let content_number = page_number + 1
    let annotation_number = page_number + 2
    let page = page_number.to_string() +
      " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents " +
      content_number.to_string() +
      " 0 R /Resources << /Font << /F1 3 0 R >> >> /Annots [" +
      annotation_number.to_string() +
      " 0 R] >>\nendobj\n"
    offsets.push(total)
    parts.push(page)
    total = total + page.length()
    let content = "BT /F1 24 Tf 72 700 Td (MoonSign compatibility page " +
      (i + 1).to_string() +
      ") Tj ET\n"
    let stream = content_number.to_string() +
      " 0 obj\n<< /Length " +
      content.length().to_string() +
      " >>\nstream\n" +
      content +
      "endstream\nendobj\n"
    offsets.push(total)
    parts.push(stream)
    total = total + stream.length()
    let annotation = annotation_number.to_string() +
      " 0 obj\n<< /Type /Annot /Subtype /Link /Rect [72 650 300 680] /A << /S /URI /URI (https://example.com/page" +
      (i + 1).to_string() +
      ") >> >>\nendobj\n"
    offsets.push(total)
    parts.push(annotation)
    total = total + annotation.length()
  }
  let xref_offset = total
  let xref = StringBuilder()
  xref.write_string("xref\n0 " + (count * 3 + 4).to_string() + "\n")
  xref.write_string("0000000000 65535 f \n")
  for offset in offsets {
    xref.write_string(pad10_offset(offset) + " 00000 n \n")
  }
  xref.write_string(
    "trailer\n<< /Size " +
    (count * 3 + 4).to_string() +
    " /Root 1 0 R >>\nstartxref\n" +
    xref_offset.to_string() +
    "\n%%EOF\n",
  )
  parts.push(xref.to_string())
  let combined = StringBuilder()
  for part in parts {
    combined.write_string(part)
  }
  @utf8.encode(combined.to_string())
}

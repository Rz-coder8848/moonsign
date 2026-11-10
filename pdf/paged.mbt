///|
fn pad10_number(value : Int32) -> String {
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
/// Build a minimal, valid PDF with `pages` empty pages.
///
/// Useful for benchmarks and for testing large documents without shipping
/// binary fixtures.
pub fn paged_pdf(pages : Int32) -> Bytes {
  let count = if pages < 1 { 1 } else { pages }
  let parts : Array[String] = []
  let offsets : Array[Int32] = []
  let mut total = 0
  let header = "%PDF-1.7\n"
  parts.push(header)
  total = total + header.length()
  let object1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
  offsets.push(total)
  parts.push(object1)
  total = total + object1.length()
  let kids = StringBuilder()
  for i in 0..<count {
    if i > 0 {
      kids.write_string(" ")
    }
    kids.write_string((3 + i).to_string() + " 0 R")
  }
  let object2 = "2 0 obj\n<< /Type /Pages /Kids [" +
    kids.to_string() +
    "] /Count " +
    count.to_string() +
    " >>\nendobj\n"
  offsets.push(total)
  parts.push(object2)
  total = total + object2.length()
  for i in 0..<count {
    let page = (3 + i).to_string() +
      " 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    offsets.push(total)
    parts.push(page)
    total = total + page.length()
  }
  let xref_offset = total
  let xref = StringBuilder()
  xref.write_string("xref\n0 " + (count + 3).to_string() + "\n")
  xref.write_string("0000000000 65535 f \n")
  for offset in offsets {
    xref.write_string(pad10_number(offset) + " 00000 n \n")
  }
  xref.write_string(
    "trailer\n<< /Size " +
    (count + 3).to_string() +
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

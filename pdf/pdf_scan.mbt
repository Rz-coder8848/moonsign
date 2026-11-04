///|
fn scan_bytes_of_ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
fn scan_slice(pdf : Bytes, start : Int32, end : Int32) -> Bytes {
  let length = end - start
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = pdf[start + i]
  }
  Bytes::from_array(out[:])
}

///|
fn scan_find(haystack : Bytes, needle : Bytes, from : Int32) -> Int32? {
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
fn scan_skip_space(pdf : Bytes, pos : Int32) -> Int32 {
  let mut index = pos
  while index < pdf.length() {
    let value = pdf[index].to_int()
    if value == 32 || value == 9 || value == 10 || value == 13 || value == 12 {
      index = index + 1
    } else {
      break
    }
  }
  index
}

///|
fn scan_int_array(pdf : Bytes, pos : Int32) -> (Array[Int32], Int32)? {
  let mut index = scan_skip_space(pdf, pos)
  if index >= pdf.length() || pdf[index].to_int() != 91 {
    return None
  }
  index = index + 1
  let values : Array[Int32] = []
  while index < pdf.length() {
    index = scan_skip_space(pdf, index)
    if index >= pdf.length() {
      return None
    }
    if pdf[index].to_int() == 93 {
      return Some((values, index + 1))
    }
    let mut value = 0
    let mut digits = 0
    while index < pdf.length() {
      let code = pdf[index].to_int()
      if code >= 48 && code <= 57 {
        value = value * 10 + (code - 48)
        digits = digits + 1
        index = index + 1
      } else {
        break
      }
    }
    if digits == 0 {
      return None
    }
    values.push(value)
  }
  None
}

///|
fn hex_value(code : Int32) -> Int32? {
  if code >= 48 && code <= 57 {
    Some(code - 48)
  } else if code >= 65 && code <= 70 {
    Some(code - 55)
  } else if code >= 97 && code <= 102 {
    Some(code - 87)
  } else {
    None
  }
}

///|
fn scan_hex_string(pdf : Bytes, pos : Int32) -> (Bytes, Int32)? {
  if pos >= pdf.length() || pdf[pos].to_int() != 60 {
    return None
  }
  let nibbles : Array[Int32] = []
  let mut index = pos + 1
  while index < pdf.length() {
    let code = pdf[index].to_int()
    if code == 62 {
      let count = nibbles.length()
      let out = Array::make((count + 1) / 2, b'\x00')
      let mut i = 0
      while i + 1 < count {
        out[i / 2] = ((nibbles[i] << 4) | nibbles[i + 1]).to_byte()
        i = i + 2
      }
      if count % 2 == 1 {
        out[count / 2] = (nibbles[count - 1] << 4).to_byte()
      }
      return Some((Bytes::from_array(out[:]), index + 1))
    }
    match hex_value(code) {
      Some(value) => nibbles.push(value)
      None =>
        if code != 32 && code != 9 && code != 10 && code != 13 {
          return None
        }
    }
    index = index + 1
  }
  None
}

///|
/// Find the last occurrence of `needle` that starts before `before`, scanning
/// back at most 4096 bytes.
/// back at most 4096 bytes.
fn scan_rfind(haystack : Bytes, needle : Bytes, before : Int32) -> Int32? {
  let start = if before > 4096 { before - 4096 } else { 0 }
  let mut found : Int32? = None
  let mut position = start
  while position < before {
    match scan_find(haystack, needle, position) {
      Some(index) =>
        if index < before {
          found = Some(index)
          position = index + 1
        } else {
          break
        }
      None => break
    }
  }
  found
}

///|
/// Find signatures by scanning PDF bytes instead of walking the xref.
///
/// This is a fallback for documents whose incremental revisions are not
/// reachable through the object table. It looks for `/ByteRange` followed by a
/// `/Contents` string; `bytes_for_signature` still validates the ranges.
pub fn signatures_scan(pdf : Bytes) -> Array[PdfSignature] {
  let out : Array[PdfSignature] = []
  let marker = scan_bytes_of_ascii("/ByteRange")
  let contents_key = scan_bytes_of_ascii("/Contents")
  let subfilter_key = scan_bytes_of_ascii("/SubFilter")
  let mut position = 0
  while true {
    let found = match scan_find(pdf, marker, position) {
      Some(index) => index
      None => break
    }
    position = found + marker.length()
    let parsed = match scan_int_array(pdf, found + marker.length()) {
      Some(value) => value
      None => continue
    }
    let (ranges, after_array) = parsed
    if ranges.length() != 4 {
      continue
    }
    let after_pos = match scan_find(pdf, contents_key, after_array) {
      Some(index) => if index - after_array > 4096 { None } else { Some(index) }
      None => None
    }
    let contents_pos = match after_pos {
      Some(index) => index
      None =>
        match scan_rfind(pdf, contents_key, found) {
          Some(index) => index
          None => continue
        }
    }
    let string_start = scan_skip_space(
      pdf,
      contents_pos + contents_key.length(),
    )
    let (contents, _) = match scan_hex_string(pdf, string_start) {
      Some(value) => value
      None => continue
    }
    let subfilter = match scan_find(pdf, subfilter_key, found) {
      Some(index) =>
        if index > contents_pos {
          ""
        } else {
          let name_start = scan_skip_space(pdf, index + subfilter_key.length())
          if name_start < pdf.length() && pdf[name_start].to_int() == 47 {
            let mut end = name_start + 1
            while end < pdf.length() {
              let code = pdf[end].to_int()
              if code == 32 ||
                code == 9 ||
                code == 10 ||
                code == 13 ||
                code == 47 ||
                code == 91 ||
                code == 60 {
                break
              }
              end = end + 1
            }
            text_of_bytes(scan_slice(pdf, name_start + 1, end))
          } else {
            ""
          }
        }
      None => ""
    }
    out.push({ field_name: "", subfilter, byte_range: ranges, contents, })
  }
  out
}

///|
/// Find signatures, preferring the structured object-table walk and falling
/// back to a byte scan when the object table cannot reach them (for example,
/// signatures added by other tools through incremental updates).
pub fn find_signatures(pdf : Bytes) -> Array[PdfSignature] {
  let structured = signatures(pdf) catch { _ => [] }
  if structured.length() > 0 {
    structured
  } else {
    signatures_scan(pdf)
  }
}

///|
/// A cursor over a DER byte buffer.
///
/// The reader owns no bytes; it points into the buffer it was created with.
pub struct DerReader {
  bytes : Bytes
  mut pos : Int32
  limit : Int32
}

///|
/// A decoded tag-length-value triple.
///
/// `content` holds the value octets (a copy), `raw` holds the full encoding
/// including tag and length (a copy). `raw` is what must be hashed or signed
/// when a structure is used as input to a signature.
pub(all) struct Tlv {
  tag : Int32
  content : Bytes
  raw : Bytes
}

///|
/// Tag class: 0 = universal, 1 = application, 2 = context-specific, 3 = private.
pub fn Tlv::tag_class(self : Tlv) -> Int32 {
  self.tag >> 6
}

///|
/// Whether the constructed bit is set.
pub fn Tlv::is_constructed(self : Tlv) -> Bool {
  (self.tag & 0x20) != 0
}

///|
/// Low-tag-number form tag number.
pub fn Tlv::tag_number(self : Tlv) -> Int32 {
  self.tag & 0x1F
}

///|
/// Create a reader over the whole buffer.
pub fn DerReader::new(bytes : Bytes) -> DerReader {
  { bytes, pos: 0, limit: bytes.length(), }
}

///|
/// Create a reader over `bytes[start:end]`.
pub fn DerReader::at(
  bytes : Bytes,
  start : Int32,
  end : Int32,
) -> DerReader raise DerError {
  if start < 0 || end < start || end > bytes.length() {
    raise DerError::InvalidLength(start)
  }
  { bytes, pos: start, limit: end, }
}

///|
/// Current byte offset.
pub fn DerReader::offset(self : DerReader) -> Int32 {
  self.pos
}

///|
/// Number of unread bytes.
pub fn DerReader::remaining(self : DerReader) -> Int32 {
  self.limit - self.pos
}

///|
/// Whether all bytes have been consumed.
pub fn DerReader::is_empty(self : DerReader) -> Bool {
  self.pos >= self.limit
}

///|
/// Peek at the next identifier octet without consuming it.
pub fn DerReader::peek_tag(self : DerReader) -> Int32? {
  if self.pos >= self.limit {
    None
  } else {
    Some(self.bytes[self.pos].to_int())
  }
}

///|
/// Read one TLV.
pub fn DerReader::read_tlv(self : DerReader) -> Tlv raise DerError {
  let start = self.pos
  if start >= self.limit {
    raise DerError::UnexpectedEnd(start)
  }
  let tag = self.bytes[start].to_int()
  if (tag & 0x1F) == 0x1F {
    raise DerError::UnsupportedTag(start)
  }
  let cursor = start + 1
  if cursor >= self.limit {
    raise DerError::UnexpectedEnd(cursor)
  }
  let first = self.bytes[cursor].to_int()
  let mut length = 0
  let mut length_octets = 0
  if first < 0x80 {
    length = first
  } else {
    if first == 0x80 {
      // Indefinite length is forbidden in DER.
      raise DerError::InvalidLength(cursor)
    }
    let count = first & 0x7F
    if count == 0 || count > 4 {
      raise DerError::LengthOverflow(cursor)
    }
    if cursor + count >= self.limit {
      raise DerError::UnexpectedEnd(cursor)
    }
    if self.bytes[cursor + 1].to_int() == 0 {
      raise DerError::NonMinimalLength(cursor)
    }
    let mut value = 0
    for i in 0..<count {
      value = (value << 8) | self.bytes[cursor + 1 + i].to_int()
    }
    length = value
    length_octets = count
  }
  let content_start = cursor + 1 + length_octets
  let content_end = content_start + length
  if content_end > self.limit {
    raise DerError::UnexpectedEnd(content_start)
  }
  let content = slice_bytes(self.bytes, content_start, content_end)
  let raw = slice_bytes(self.bytes, start, content_end)
  self.pos = content_end
  { tag, content, raw, }
}

///|
/// Read one TLV and require an exact tag.
pub fn DerReader::read_expected(
  self : DerReader,
  tag : Int32,
) -> Tlv raise DerError {
  let tlv = self.read_tlv()
  if tlv.tag != tag {
    raise DerError::UnexpectedTag(tag, tlv.tag)
  }
  tlv
}

///|
/// Read a SEQUENCE and return a reader over its content.
pub fn DerReader::read_sequence(self : DerReader) -> DerReader raise DerError {
  let tlv = self.read_expected(tag_sequence)
  DerReader::at(tlv.content, 0, tlv.content.length())
}

///|
/// Read a SET and return a reader over its content.
pub fn DerReader::read_set(self : DerReader) -> DerReader raise DerError {
  let tlv = self.read_expected(tag_set)
  DerReader::at(tlv.content, 0, tlv.content.length())
}

///|
/// Read every remaining TLV in the reader.
pub fn DerReader::read_all(self : DerReader) -> Array[Tlv] raise DerError {
  let out : Array[Tlv] = []
  while !self.is_empty() {
    out.push(self.read_tlv())
  }
  out
}

///|
/// Read a small non-negative INTEGER (used for version numbers).
pub fn DerReader::read_integer_int(self : DerReader) -> Int32 raise DerError {
  let tlv = self.read_expected(tag_integer)
  let content = tlv.content
  if content.length() == 0 || content.length() > 4 {
    raise DerError::InvalidInteger(self.pos)
  }
  let mut value = 0
  for i in 0..<content.length() {
    value = (value << 8) | content[i].to_int()
  }
  if (content[0].to_int() & 0x80) != 0 {
    // Negative values are not expected in this position; reject rather than
    // silently interpreting them as large positives.
    raise DerError::InvalidInteger(self.pos)
  }
  value
}

///|
/// Read an OBJECT IDENTIFIER as a dotted string.
pub fn DerReader::read_oid(self : DerReader) -> String raise DerError {
  let tlv = self.read_expected(tag_oid)
  decode_oid(tlv.content)
}

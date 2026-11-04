///|
/// Encode a DER length octet sequence.
pub fn der_encode_length(length : Int32) -> Bytes {
  if length < 0 {
    abort("der: negative length")
  }
  if length < 0x80 {
    let one = Array::make(1, length.to_byte())
    return Bytes::from_array(one[:])
  }
  let tmp = Array::make(4, b'\x00')
  let mut count = 0
  let mut value = length
  while value > 0 {
    tmp[3 - count] = (value & 0xFF).to_byte()
    count = count + 1
    value = value >> 8
  }
  if count > 4 {
    abort("der: length does not fit in four octets")
  }
  let out = Array::make(count + 1, b'\x00')
  out[0] = (0x80 | count).to_byte()
  for i in 0..<count {
    out[1 + i] = tmp[4 - count + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Encode one TLV with the given identifier octet and content.
pub fn der_encode(tag : Int32, content : Bytes) -> Bytes {
  let head = Array::make(1, tag.to_byte())
  der_bytes_concat([
    Bytes::from_array(head[:]),
    der_encode_length(content.length()),
    content,
  ])
}

///|
/// Encode a SEQUENCE from already-encoded members.
pub fn der_sequence(parts : Array[Bytes]) -> Bytes {
  der_encode(tag_sequence, der_bytes_concat(parts))
}

///|
/// Encode a SET OF from already-encoded members.
///
/// DER requires the members of a SET OF to be sorted by their encodings, so
/// this function always sorts a copy of the input.
pub fn der_set(parts : Array[Bytes]) -> Bytes {
  let sorted : Array[Bytes] = []
  for part in parts {
    sorted.push(part)
  }
  let n = sorted.length()
  if n > 1 {
    for i in 1..<n {
      let mut j = i
      while j > 0 && der_bytes_compare(sorted[j - 1], sorted[j]) > 0 {
        let tmp = sorted[j - 1]
        sorted[j - 1] = sorted[j]
        sorted[j] = tmp
        j = j - 1
      }
    }
  }
  der_encode(tag_set, der_bytes_concat(sorted))
}

///|
/// Encode an OCTET STRING.
pub fn der_octet_string(content : Bytes) -> Bytes {
  der_encode(tag_octet_string, content)
}

///|
/// Encode a BIT STRING with the given number of unused trailing bits.
pub fn der_bit_string(content : Bytes, unused_bits : Int32) -> Bytes {
  if unused_bits < 0 || unused_bits > 7 {
    abort("der: unused_bits must be in 0..7")
  }
  let body = Array::make(content.length() + 1, b'\x00')
  body[0] = unused_bits.to_byte()
  for i in 0..<content.length() {
    body[1 + i] = content[i]
  }
  der_encode(tag_bit_string, Bytes::from_array(body[:]))
}

///|
/// Encode a non-negative INTEGER from its big-endian magnitude bytes.
///
/// Leading zero bytes are stripped; if the most significant bit would be set,
/// a leading zero octet is added so the value stays positive.
pub fn der_integer_bytes(magnitude : Bytes) -> Bytes {
  let mut start = 0
  while start < magnitude.length() && magnitude[start].to_int() == 0 {
    start = start + 1
  }
  let significant = magnitude.length() - start
  if significant == 0 {
    let zero = Array::make(1, b'\x00')
    return der_encode(tag_integer, Bytes::from_array(zero[:]))
  }
  let needs_pad = (magnitude[start].to_int() & 0x80) != 0
  let length = significant + (if needs_pad { 1 } else { 0 })
  let out = Array::make(length, b'\x00')
  let offset = if needs_pad { 1 } else { 0 }
  for i in 0..<significant {
    out[offset + i] = magnitude[start + i]
  }
  der_encode(tag_integer, Bytes::from_array(out[:]))
}

///|
/// Encode a small non-negative INTEGER.
pub fn der_integer_int(value : Int32) -> Bytes {
  if value < 0 {
    abort("der: negative integers are not supported by der_integer_int")
  }
  if value == 0 {
    let zero = Array::make(1, b'\x00')
    return der_encode(tag_integer, Bytes::from_array(zero[:]))
  }
  let tmp = Array::make(4, b'\x00')
  let mut count = 0
  let mut v = value
  while v > 0 {
    tmp[3 - count] = (v & 0xFF).to_byte()
    count = count + 1
    v = v >> 8
  }
  let magnitude = Array::make(count, b'\x00')
  for i in 0..<count {
    magnitude[i] = tmp[4 - count + i]
  }
  der_integer_bytes(Bytes::from_array(magnitude[:]))
}

///|
/// Encode a BOOLEAN.
pub fn der_boolean(value : Bool) -> Bytes {
  let body = Array::make(1, if value { b'\xff' } else { b'\x00' })
  der_encode(tag_boolean, Bytes::from_array(body[:]))
}

///|
/// Encode NULL.
pub fn der_null() -> Bytes {
  der_encode(tag_null, Bytes::from_array(Array::make(0, b'\x00')[:]))
}

///|
/// Encode a UTF8String.
pub fn der_utf8_string(value : String) -> Bytes {
  der_encode(tag_utf8_string, @utf8.encode(value))
}

///|
/// Encode a context-specific tag.
pub fn der_context(
  tag_number : Int32,
  constructed : Bool,
  content : Bytes,
) -> Bytes {
  if tag_number < 0 || tag_number > 30 {
    abort("der: context tag number must be in 0..30")
  }
  let tag = 0x80 | (if constructed { 0x20 } else { 0x00 }) | tag_number
  der_encode(tag, content)
}

///|
/// Encode an explicit context-specific tag (constructed, content is a TLV).
pub fn der_context_explicit(tag_number : Int32, inner : Bytes) -> Bytes {
  der_context(tag_number, true, inner)
}

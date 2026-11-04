///|
/// Append one base-128 subidentifier to `out`.
fn encode_subidentifier(out : Array[Byte], value : Int32) -> Unit {
  let tmp = Array::make(5, b'\x00')
  let mut count = 0
  let mut v = value
  while true {
    tmp[count] = (v & 0x7F).to_byte()
    count = count + 1
    v = v >> 7
    if v == 0 {
      break
    }
  }
  for i in 0..<count {
    let index = count - 1 - i
    let mut byte = tmp[index].to_int()
    if index > 0 {
      byte = byte | 0x80
    }
    out.push(byte.to_byte())
  }
}

///|
/// Encode an OBJECT IDENTIFIER from its arcs.
///
/// Aborts on invalid arcs; use `der_oid_parse` when the input comes from
/// untrusted text.
pub fn der_oid(arcs : Array[Int32]) -> Bytes {
  if arcs.length() < 2 {
    abort("der: an OID needs at least two arcs")
  }
  let first = arcs[0]
  let second = arcs[1]
  if first < 0 || first > 2 || second < 0 || (first < 2 && second > 39) {
    abort("der: invalid OID arcs")
  }
  let out : Array[Byte] = []
  encode_subidentifier(out, first * 40 + second)
  for i in 2..<arcs.length() {
    let arc = arcs[i]
    if arc < 0 {
      abort("der: negative OID arc")
    }
    encode_subidentifier(out, arc)
  }
  der_encode(tag_oid, Bytes::from_array(out[:]))
}

///|
/// Parse a dotted OID string (for example `"1.2.840.113549.1.7.2"`) and encode it.
pub fn der_oid_parse(dotted : String) -> Bytes raise DerError {
  let arcs : Array[Int32] = []
  let mut value = 0
  let mut digits = 0
  let length = dotted.length()
  for i in 0..<length {
    match dotted.get_char(i) {
      Some(c) =>
        if c == '.' {
          if digits == 0 {
            raise DerError::InvalidOid(i)
          }
          arcs.push(value)
          value = 0
          digits = 0
        } else {
          let digit = c.to_int() - 48
          if digit < 0 || digit > 9 {
            raise DerError::InvalidOid(i)
          }
          value = value * 10 + digit
          digits = digits + 1
          if digits > 9 {
            raise DerError::InvalidOid(i)
          }
        }
      None => raise DerError::InvalidOid(i)
    }
  }
  if digits == 0 {
    raise DerError::InvalidOid(length)
  }
  arcs.push(value)
  if arcs.length() < 2 {
    raise DerError::InvalidOid(0)
  }
  if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
    raise DerError::InvalidOid(0)
  }
  der_oid(arcs)
}

///|
/// Decode OID content octets into a dotted string.
pub fn decode_oid(content : Bytes) -> String raise DerError {
  if content.length() == 0 {
    raise DerError::InvalidOid(0)
  }
  let values : Array[Int32] = []
  let mut value = 0
  let mut in_progress = false
  for i in 0..<content.length() {
    let byte = content[i].to_int()
    if !in_progress && byte == 0x80 {
      raise DerError::InvalidOid(i)
    }
    value = (value << 7) | (byte & 0x7F)
    in_progress = true
    if (byte & 0x80) == 0 {
      values.push(value)
      value = 0
      in_progress = false
    }
  }
  if in_progress || values.length() == 0 {
    raise DerError::InvalidOid(content.length())
  }
  let first = values[0]
  let (class_arc, second_arc) = if first < 40 {
    (0, first)
  } else if first < 80 {
    (1, first - 40)
  } else {
    (2, first - 80)
  }
  let buf = StringBuilder()
  buf.write_string(class_arc.to_string())
  buf.write_string(".")
  buf.write_string(second_arc.to_string())
  for i in 1..<values.length() {
    buf.write_string(".")
    buf.write_string(values[i].to_string())
  }
  buf.to_string()
}

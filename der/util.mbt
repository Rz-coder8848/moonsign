///|
/// Copy `bytes[start:end]` into a fresh `Bytes`.
///
/// MoonBit slices are views; DER parsing needs owned copies because a `Tlv`
/// may outlive the reader that produced it.
fn slice_bytes(bytes : Bytes, start : Int32, end : Int32) -> Bytes {
  let length = end - start
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = bytes[start + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Concatenate byte strings in order.
pub fn der_bytes_concat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for part in parts {
    total = total + part.length()
  }
  let out = Array::make(total, b'\x00')
  let mut offset = 0
  for part in parts {
    for i in 0..<part.length() {
      out[offset + i] = part[i]
    }
    offset = offset + part.length()
  }
  Bytes::from_array(out[:])
}

///|
/// Lexicographic comparison of two byte strings (used for DER SET OF sorting).
pub fn der_bytes_compare(a : Bytes, b : Bytes) -> Int32 {
  let common = if a.length() < b.length() { a.length() } else { b.length() }
  for i in 0..<common {
    let x = a[i].to_int()
    let y = b[i].to_int()
    if x < y {
      return -1
    }
    if x > y {
      return 1
    }
  }
  if a.length() < b.length() {
    -1
  } else if a.length() > b.length() {
    1
  } else {
    0
  }
}

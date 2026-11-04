///|
fn fixture_char_at(text : String, index : Int32) -> Char {
  match text.get_char(index) {
    Some(c) => c
    None => abort("fixture hex: index out of range")
  }
}

///|
fn fixture_hex_digit(c : Char) -> Int32 {
  let code = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("fixture hex: invalid digit")
  }
}

///|
/// Decode a lowercase/uppercase hex string into bytes.
///
/// The input must have an even number of digits; fixtures are generated with
/// `scripts/gen_fixtures.py`, which normalizes lengths.
pub fn bytes_of_hex(text : String) -> Bytes {
  if text.length() % 2 != 0 {
    abort("fixture hex: odd number of digits")
  }
  let count = text.length() / 2
  let out = Array::make(count, b'\x00')
  for i in 0..<count {
    let hi = fixture_hex_digit(fixture_char_at(text, i * 2))
    let lo = fixture_hex_digit(fixture_char_at(text, i * 2 + 1))
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// Encode bytes as lowercase hex (used by fixture assertions).
pub fn hex_of_bytes(bytes : Bytes) -> String {
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    buf.write_string(bytes[i].to_hex())
  }
  buf.to_string()
}

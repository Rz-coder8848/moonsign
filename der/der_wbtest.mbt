///|
fn synth_hex(bytes : Bytes) -> String {
  let buf = StringBuilder()
  for i in 0..<bytes.length() {
    buf.write_string(bytes[i].to_hex())
  }
  buf.to_string()
}

///|
fn synth_char_at(text : String, index : Int32) -> Char {
  match text.get_char(index) {
    Some(c) => c
    None => abort("index out of range")
  }
}

///|
fn synth_hex_digit(c : Char) -> Int32 {
  let code = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("invalid hex digit")
  }
}

///|
fn synth_bytes_of_hex(text : String) -> Bytes {
  let out = Array::make(text.length() / 2, b'\x00')
  for i in 0..<out.length() {
    let hi = synth_hex_digit(synth_char_at(text, i * 2))
    let lo = synth_hex_digit(synth_char_at(text, i * 2 + 1))
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
test "length encoding" {
  inspect(synth_hex(der_encode_length(0)), content="00")
  inspect(synth_hex(der_encode_length(127)), content="7f")
  inspect(synth_hex(der_encode_length(128)), content="8180")
  inspect(synth_hex(der_encode_length(255)), content="81ff")
  inspect(synth_hex(der_encode_length(256)), content="820100")
  inspect(synth_hex(der_encode_length(65535)), content="82ffff")
}

///|
test "integer encoding" {
  inspect(synth_hex(der_integer_int(0)), content="020100")
  inspect(synth_hex(der_integer_int(127)), content="02017f")
  inspect(synth_hex(der_integer_int(128)), content="02020080")
  inspect(synth_hex(der_integer_int(255)), content="020200ff")
  inspect(synth_hex(der_integer_int(256)), content="02020100")
}

///|
test "oid known vectors" {
  let signed_data = der_oid([1, 2, 840, 113549, 1, 7, 2])
  inspect(synth_hex(signed_data), content="06092a864886f70d010702")
  inspect(
    decode_oid(DerReader::new(signed_data).read_tlv().content),
    content="1.2.840.113549.1.7.2",
  )
  let large_second = der_oid([2, 999, 3])
  inspect(synth_hex(large_second), content="0603883703")
  inspect(
    decode_oid(DerReader::new(large_second).read_tlv().content),
    content="2.999.3",
  )
}

///|
test "oid string parsing" {
  inspect(
    synth_hex(der_oid_parse("1.2.840.113549.1.7.2")),
    content="06092a864886f70d010702",
  )
  let ok = try {
    let _ = der_oid_parse("1.2.bad")
    false
  } catch {
    _ => true
  }
  inspect(ok, content="true")
}

///|
test "set of is sorted by encoding" {
  let one = der_sequence([der_integer_int(1)])
  let two = der_sequence([der_integer_int(2)])
  let encoded = der_set([two, one])
  inspect(synth_hex(encoded), content="310a30030201013003020102")
}

///|
test "utc time vectors" {
  inspect(synth_hex(der_utc_time(0)), content="170d3730303130313030303030305a")
  inspect(
    synth_hex(der_utc_time(1793793600)),
    content="170d3236313130343132303030305a",
  )
  inspect(
    synth_hex(der_time_auto(2524607999)),
    content="170d3439313233313233353935395a",
  )
  inspect(
    synth_hex(der_time_auto(2524608000)),
    content="180f32303530303130313030303030305a",
  )
}

///|
test "time round trip" {
  let unix = 951827696L
  let encoded = der_time_auto(unix)
  let tlv = DerReader::new(encoded).read_tlv()
  inspect(der_time_parse(tlv), content="951827696")
}

///|
test "reader rejects truncated input" {
  let bytes = synth_bytes_of_hex("30050201")
  let failed = try {
    let _ = DerReader::new(bytes).read_tlv()
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
test "reader rejects indefinite length" {
  let bytes = synth_bytes_of_hex("308002010000")
  let failed = try {
    let _ = DerReader::new(bytes).read_tlv()
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
test "reader rejects non-minimal length" {
  let bytes = synth_bytes_of_hex("30820001ff")
  let failed = try {
    let _ = DerReader::new(bytes).read_tlv()
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

///|
test "context tags" {
  let inner = der_integer_int(1)
  let explicit = der_context_explicit(0, inner)
  inspect(synth_hex(explicit), content="a003020101")
  let implicit = der_context(1, false, synth_bytes_of_hex("ff"))
  inspect(synth_hex(implicit), content="8101ff")
}

///|
test "sequence round trip" {
  let seq = der_sequence([
    der_integer_int(3),
    der_oid_parse("1.2.840.113549.1.7.1"),
  ])
  let reader = DerReader::new(seq).read_sequence()
  inspect(reader.read_integer_int(), content="3")
  inspect(reader.read_oid(), content="1.2.840.113549.1.7.1")
  inspect(reader.is_empty(), content="true")
}

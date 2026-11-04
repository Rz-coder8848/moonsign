///|
fn ascii_of(bytes : Bytes, start : Int32, length : Int32) -> String {
  let buf = StringBuilder()
  for i in 0..<length {
    buf.write_char(bytes[start + i].to_char())
  }
  buf.to_string()
}

///|
test "prepare adds a placeholder revision" {
  let base = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => fail("failed to create the minimal PDF")
  }
  let bytes = @pdflite.pdf_write_document(base) catch {
    _ => fail("failed to serialize the minimal PDF")
  }
  let prepared = prepare(bytes, "Signature1", 4096) catch {
    _ => fail("prepare failed")
  }
  inspect(prepared.length() > bytes.length(), content="true")
  // The rewritten document must still parse.
  let reparsed_prepared = @pdflite.pdf_read_document_from_bytes(prepared) catch {
    _ => fail("prepared PDF does not parse")
  }
  inspect(reparsed_prepared.page_reference_numbers().length(), content="1")
  let slot = locate(prepared, 4096) catch { _ => fail("locate failed") }
  inspect(prepared[slot.open_pos].to_int(), content="40")
  inspect(prepared[slot.close_pos].to_int(), content="41")
  let ranges = signed_ranges(prepared, slot)
  inspect(ranges.length(), content="2")
  inspect(
    ranges[0].length() + ranges[1].length() + 4098,
    content=prepared.length().to_string(),
  )
}

///|
test "embed writes ByteRange and hex contents" {
  let base = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => fail("failed to create the minimal PDF")
  }
  let bytes = @pdflite.pdf_write_document(base) catch {
    _ => fail("failed to serialize the minimal PDF")
  }
  let prepared = prepare(bytes, "Signature1", 4096) catch {
    _ => fail("prepare failed")
  }
  let (sealed_pdf, slot) = seal_layout(prepared, 4096) catch {
    _ => fail("seal failed")
  }
  let fake = Array::make(64, b'\x30')
  let signed = embed(sealed_pdf, slot, Bytes::from_array(fake[:])) catch {
    _ => fail("embed failed")
  }
  inspect(signed[slot.open_pos].to_int(), content="60")
  inspect(signed[slot.close_pos].to_int(), content="62")
  let expected_range = "[" +
    pad10(0) +
    " " +
    pad10(slot.open_pos) +
    " " +
    pad10(slot.close_pos + 1) +
    " " +
    pad10(signed.length() - (slot.close_pos + 1)) +
    "]"
  inspect(ascii_of(signed, slot.byte_range_pos, 45), content=expected_range)
  // The signature hex must start with the fake DER bytes.
  inspect(ascii_of(signed, slot.open_pos + 1, 8), content="30303030")
  // The signed file must still be a valid PDF.
  let reparsed = @pdflite.pdf_read_document_from_bytes(signed) catch {
    _ => fail("signed PDF no longer parses")
  }
  inspect(reparsed.page_reference_numbers().length(), content="1")
}

///|
test "embed rejects an oversized signature" {
  let base = @pdflite.pdf_minimum_valid_pdf() catch {
    _ => fail("failed to create the minimal PDF")
  }
  let bytes = @pdflite.pdf_write_document(base) catch {
    _ => fail("failed to serialize the minimal PDF")
  }
  let prepared = prepare(bytes, "Signature1", 64) catch {
    _ => fail("prepare failed")
  }
  let (sealed_pdf, slot) = seal_layout(prepared, 64) catch {
    _ => fail("seal failed")
  }
  let oversized = Array::make(64, b'\x00')
  let failed = try {
    let _ = embed(sealed_pdf, slot, Bytes::from_array(oversized[:]))
    false
  } catch {
    _ => true
  }
  inspect(failed, content="true")
}

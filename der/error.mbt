///|
/// Errors raised while reading or writing DER.
///
/// Offsets are byte offsets into the input buffer so callers can point at the
/// exact location that failed.
pub(all) suberror DerError {
  /// The input ended before a complete TLV could be read.
  UnexpectedEnd(Int32)
  /// High-tag-number form (tag number >= 31) is not supported.
  UnsupportedTag(Int32)
  /// Indefinite length or a malformed length octet.
  InvalidLength(Int32)
  /// A length that does not fit in the supported range.
  LengthOverflow(Int32)
  /// A long-form length with a redundant leading zero (DER forbids it).
  NonMinimalLength(Int32)
  /// A tag that is structurally invalid for the requested operation.
  InvalidTag(Int32)
  /// The expected tag did not match the actual tag.
  UnexpectedTag(Int32, Int32)
  /// Bytes remained after a complete structure was read.
  TrailingBytes(Int32)
  /// An INTEGER was malformed or out of the supported range.
  InvalidInteger(Int32)
  /// An OBJECT IDENTIFIER was malformed.
  InvalidOid(Int32)
  /// A UTCTime / GeneralizedTime was malformed.
  InvalidTime(Int32)
}

///|
/// Byte offset associated with an error, when the variant carries one.
pub fn DerError::offset(self : DerError) -> Int32 {
  match self {
    UnexpectedEnd(offset) => offset
    UnsupportedTag(offset) => offset
    InvalidLength(offset) => offset
    LengthOverflow(offset) => offset
    NonMinimalLength(offset) => offset
    InvalidTag(offset) => offset
    UnexpectedTag(_, _) => 0
    TrailingBytes(offset) => offset
    InvalidInteger(offset) => offset
    InvalidOid(offset) => offset
    InvalidTime(offset) => offset
  }
}

///|
/// Human-readable description of a DER error.
pub fn DerError::message(self : DerError) -> String {
  match self {
    UnexpectedEnd(offset) => "unexpected end of input at byte \{offset}"
    UnsupportedTag(offset) =>
      "unsupported high-tag-number form at byte \{offset}"
    InvalidLength(offset) => "invalid DER length at byte \{offset}"
    LengthOverflow(offset) => "DER length too large at byte \{offset}"
    NonMinimalLength(offset) => "non-minimal DER length at byte \{offset}"
    InvalidTag(offset) => "invalid tag at byte \{offset}"
    UnexpectedTag(expected, actual) =>
      "unexpected tag: expected 0x\{expected.to_string(radix=16)}, got 0x\{actual.to_string(radix=16)}"
    TrailingBytes(offset) => "trailing bytes after structure at byte \{offset}"
    InvalidInteger(offset) => "invalid INTEGER at byte \{offset}"
    InvalidOid(offset) => "invalid OBJECT IDENTIFIER at byte \{offset}"
    InvalidTime(offset) => "invalid time value at byte \{offset}"
  }
}

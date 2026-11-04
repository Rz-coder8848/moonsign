///|
/// Floor division for `Int64`.
fn floor_div64(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  let r = a % b
  if r != 0 && (r < 0) != (b < 0) {
    q - 1
  } else {
    q
  }
}

///|
/// Convert a count of days since 1970-01-01 into a civil (year, month, day).
///
/// Howard Hinnant's `civil_from_days`, valid for the proleptic Gregorian
/// calendar.
fn civil_from_days(days : Int32) -> (Int32, Int32, Int32) {
  let z = days + 719468
  let era = (if z >= 0 { z } else { z - 146096 }) / 146097
  let doe = z - era * 146097
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let y = yoe + era * 400
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp = (5 * doy + 2) / 153
  let d = doy - (153 * mp + 2) / 5 + 1
  let m = mp + (if mp < 10 { 3 } else { -9 })
  let year = y + (if m <= 2 { 1 } else { 0 })
  (year, m, d)
}

///|
/// Inverse of `civil_from_days`.
fn days_from_civil(year : Int32, month : Int32, day : Int32) -> Int32 {
  let y = year - (if month <= 2 { 1 } else { 0 })
  let era = (if y >= 0 { y } else { y - 399 }) / 400
  let yoe = y - era * 400
  let mp = if month > 2 { month - 3 } else { month + 9 }
  let doy = (153 * mp + 2) / 5 + day - 1
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
  era * 146097 + doe - 719468
}

///|
fn pad2(value : Int32) -> String {
  if value < 10 {
    "0" + value.to_string()
  } else {
    value.to_string()
  }
}

///|
fn pad4(value : Int32) -> String {
  if value < 10 {
    "000" + value.to_string()
  } else if value < 100 {
    "00" + value.to_string()
  } else if value < 1000 {
    "0" + value.to_string()
  } else {
    value.to_string()
  }
}

///|
/// Split a Unix timestamp into (year, month, day, hour, minute, second).
fn split_unix(unix : Int64) -> (Int32, Int32, Int32, Int32, Int32, Int32) {
  let day_seconds = Int64::from_int(86400)
  let days64 = floor_div64(unix, day_seconds)
  let seconds_of_day = unix - days64 * day_seconds
  let days = days64.to_int()
  let (year, month, day) = civil_from_days(days)
  let hour = (seconds_of_day / Int64::from_int(3600)).to_int()
  let minute = (seconds_of_day % Int64::from_int(3600) / Int64::from_int(60)).to_int()
  let second = (seconds_of_day % Int64::from_int(60)).to_int()
  (year, month, day, hour, minute, second)
}

///|
/// Encode a UTCTime (`YYMMDDHHMMSSZ`).
pub fn der_utc_time(unix : Int64) -> Bytes {
  let (year, month, day, hour, minute, second) = split_unix(unix)
  let yy = (year % 100 + 100) % 100
  let text = pad2(yy) +
    pad2(month) +
    pad2(day) +
    pad2(hour) +
    pad2(minute) +
    pad2(second) +
    "Z"
  der_encode(tag_utc_time, @utf8.encode(text))
}

///|
/// Encode a GeneralizedTime (`YYYYMMDDHHMMSSZ`).
pub fn der_generalized_time(unix : Int64) -> Bytes {
  let (year, month, day, hour, minute, second) = split_unix(unix)
  let text = pad4(year) +
    pad2(month) +
    pad2(day) +
    pad2(hour) +
    pad2(minute) +
    pad2(second) +
    "Z"
  der_encode(tag_generalized_time, @utf8.encode(text))
}

///|
/// Encode a time, choosing UTCTime for 1950..2049 and GeneralizedTime outside
/// that range (RFC 5280 搂4.1.2.5).
pub fn der_time_auto(unix : Int64) -> Bytes {
  let (year, _, _, _, _, _) = split_unix(unix)
  if year >= 1950 && year <= 2049 {
    der_utc_time(unix)
  } else {
    der_generalized_time(unix)
  }
}

///|
fn digit_at(content : Bytes, offset : Int32) -> Int32 raise DerError {
  if offset >= content.length() {
    raise DerError::InvalidTime(offset)
  }
  let d = content[offset].to_int() - 48
  if d < 0 || d > 9 {
    raise DerError::InvalidTime(offset)
  }
  d
}

///|
fn digits2(content : Bytes, offset : Int32) -> Int32 raise DerError {
  digit_at(content, offset) * 10 + digit_at(content, offset + 1)
}

///|
fn digits4(content : Bytes, offset : Int32) -> Int32 raise DerError {
  digit_at(content, offset) * 1000 +
  digit_at(content, offset + 1) * 100 +
  digit_at(content, offset + 2) * 10 +
  digit_at(content, offset + 3)
}

///|
/// Parse a UTCTime or GeneralizedTime TLV into Unix seconds.
///
/// Only the `Z` (UTC) form with seconds precision is accepted, which is what
/// RFC 5280 requires for certificate and CMS signing times.
pub fn der_time_parse(tlv : Tlv) -> Int64 raise DerError {
  let content = tlv.content
  let mut year = 0
  let mut offset = 0
  if tlv.tag == tag_utc_time {
    if content.length() != 13 {
      raise DerError::InvalidTime(0)
    }
    let yy = digits2(content, 0)
    year = if yy >= 50 { 1900 + yy } else { 2000 + yy }
    offset = 2
  } else if tlv.tag == tag_generalized_time {
    if content.length() != 15 {
      raise DerError::InvalidTime(0)
    }
    year = digits4(content, 0)
    offset = 4
  } else {
    raise DerError::UnexpectedTag(tag_utc_time, tlv.tag)
  }
  let month = digits2(content, offset)
  let day = digits2(content, offset + 2)
  let hour = digits2(content, offset + 4)
  let minute = digits2(content, offset + 6)
  let second = digits2(content, offset + 8)
  if content[offset + 10].to_int() != 90 {
    raise DerError::InvalidTime(offset + 10)
  }
  if month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 {
    raise DerError::InvalidTime(offset)
  }
  let days = days_from_civil(year, month, day)
  let seconds = days * 86400 + hour * 3600 + minute * 60 + second
  Int64::from_int(seconds)
}

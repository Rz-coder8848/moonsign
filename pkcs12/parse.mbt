///|
/// Errors raised while reading a PKCS#12 file.
pub(all) suberror Pkcs12Error {
  Der(@der.DerError)
  X509(@x509.X509Error)
  BadPassword
  BadStructure(String)
  Unsupported(String)
}

///|
/// Certificates and (optionally) the private key found in a PKCS#12 file.
pub(all) struct Pkcs12 {
  certificates : Array[@x509.Certificate]
  /// PKCS#8 DER of the private key, when present.
  private_key_der : Bytes?
}

///|
fn read_tlv(reader : @der.DerReader) -> @der.Tlv raise Pkcs12Error {
  reader.read_tlv() catch {
    e => raise Pkcs12Error::Der(e)
  }
}

///|
fn read_seq(reader : @der.DerReader) -> @der.DerReader raise Pkcs12Error {
  reader.read_sequence() catch {
    e => raise Pkcs12Error::Der(e)
  }
}

///|
fn read_oid(reader : @der.DerReader) -> String raise Pkcs12Error {
  reader.read_oid() catch {
    e => raise Pkcs12Error::Der(e)
  }
}

///|
fn read_int(reader : @der.DerReader) -> Int32 raise Pkcs12Error {
  reader.read_integer_int() catch {
    e => raise Pkcs12Error::Der(e)
  }
}

///|
fn reader_at(bytes : Bytes) -> @der.DerReader raise Pkcs12Error {
  @der.DerReader::at(bytes, 0, bytes.length()) catch {
    e => raise Pkcs12Error::Der(e)
  }
}

///|
fn hash_of_oid(oid : String) -> @crypto.Hash raise Pkcs12Error {
  if oid == "1.3.14.3.2.26" {
    @crypto.Hash::Sha1
  } else if oid == "2.16.840.1.101.3.4.2.1" {
    @crypto.Hash::Sha256
  } else {
    raise Pkcs12Error::Unsupported("MAC hash: " + oid)
  }
}

///|
fn repeat_to(value : Bytes, multiple : Int32) -> Bytes {
  if value.length() == 0 {
    return Bytes::from_array([])
  }
  let length = (value.length() + multiple - 1) / multiple * multiple
  let out = Array::make(length, b'\x00')
  for i in 0..<length {
    out[i] = value[i % value.length()]
  }
  Bytes::from_array(out[:])
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut length = 0
  for part in parts {
    length = length + part.length()
  }
  let out = Array::make(length, b'\x00')
  let mut pos = 0
  for part in parts {
    for i in 0..<part.length() {
      out[pos] = part[i]
      pos = pos + 1
    }
  }
  Bytes::from_array(out[:])
}

///|
fn pkcs12_kdf(
  hash : @crypto.Hash,
  password : Bytes,
  salt : Bytes,
  id : Int32,
  iterations : Int32,
  key_length : Int32,
) -> Bytes {
  let block = 64
  let d = repeat_to(Bytes::from_array([id.to_byte()]), block)
  let s = repeat_to(salt, block)
  let p = repeat_to(password, block)
  let i_bytes = concat_bytes([d, s, p])
  let mut a = @crypto.digest(hash, i_bytes)
  for _ in 1..<iterations {
    a = @crypto.digest(hash, a)
  }
  let out = Array::make(key_length, b'\x00')
  for i in 0..<key_length {
    out[i] = a[i]
  }
  Bytes::from_array(out[:])
}

///|
fn bmp_password(password : String) -> Bytes {
  let length = password.length() * 2 + 2
  let out = Array::make(length, b'\x00')
  for i in 0..<password.length() {
    let code = password.get_char(i).unwrap().to_int()
    out[i * 2] = (code >> 8).to_byte()
    out[i * 2 + 1] = (code & 0xFF).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
fn decrypt_pbes2(
  algorithm : @der.DerReader,
  ciphertext : Bytes,
  password_utf8 : Bytes,
  password_bmp : Bytes,
) -> Bytes raise Pkcs12Error {
  let algorithm_sequence = read_seq(algorithm)
  let algorithm_oid = read_oid(algorithm_sequence)
  if algorithm_oid != @oids.pbes2 {
    raise Pkcs12Error::Unsupported("encryption algorithm: " + algorithm_oid)
  }
  let parameters = read_seq(algorithm_sequence)
  let kdf = read_seq(parameters)
  let kdf_oid = read_oid(kdf)
  if kdf_oid != @oids.pbkdf2 {
    raise Pkcs12Error::Unsupported("key derivation: " + kdf_oid)
  }
  let kdf_parameters = read_seq(kdf)
  let salt = read_tlv(kdf_parameters)
  let iterations = read_int(kdf_parameters)
  let mut key_length = 0
  match kdf_parameters.peek_tag() {
    Some(tag) => if tag == 0x02 { key_length = read_int(kdf_parameters) }
    None => ()
  }
  let mut prf = @oids.hmac_with_sha1
  match kdf_parameters.peek_tag() {
    Some(tag) =>
      if tag == 0x30 {
        let prf_algorithm = read_seq(kdf_parameters)
        prf = read_oid(prf_algorithm)
      }
    None => ()
  }
  let encryption = read_seq(parameters)
  let encryption_oid = read_oid(encryption)
  let iv = read_tlv(encryption)
  let aes_length = if encryption_oid == @oids.aes128_cbc {
    16
  } else if encryption_oid == @oids.aes192_cbc {
    24
  } else if encryption_oid == @oids.aes256_cbc {
    32
  } else {
    raise Pkcs12Error::Unsupported("cipher: " + encryption_oid)
  }
  let length = if key_length > 0 { key_length } else { aes_length }
  for candidate in [password_utf8, password_bmp] {
    let key = if prf == @oids.hmac_with_sha1 {
      @crypto.pbkdf2_sha1(candidate, salt.content, iterations, length)
    } else if prf == @oids.hmac_with_sha256 {
      @crypto.pbkdf2_sha256(candidate, salt.content, iterations, length)
    } else {
      raise Pkcs12Error::Unsupported("PBKDF2 PRF: " + prf)
    }
    match @crypto.aes_cbc_decrypt_checked(ciphertext, key, iv.content) {
      Ok(value) => return value
      Err(_) => ()
    }
  }
  raise Pkcs12Error::BadPassword
}

///|
fn decrypt_encrypted_data(
  bytes : Bytes,
  password_utf8 : Bytes,
  password_bmp : Bytes,
) -> Bytes raise Pkcs12Error {
  let reader = reader_at(bytes)
  let sequence = read_seq(reader)
  let _version = read_int(sequence)
  let info = read_seq(sequence)
  let _content_type = read_oid(info)
  let algorithm = read_tlv(info)
  let content = read_tlv(info)
  if content.tag != 0x80 {
    raise Pkcs12Error::BadStructure("encryptedContent is missing")
  }
  decrypt_pbes2(
    reader_at(algorithm.raw),
    content.content,
    password_utf8,
    password_bmp,
  )
}

///|
fn verify_mac(
  mac_data : @der.DerReader,
  auth_bytes : Bytes,
  password_bmp : Bytes,
  password_utf8 : Bytes,
) -> Unit raise Pkcs12Error {
  let mac_info = read_seq(mac_data)
  let digest_info = read_seq(mac_info)
  let algorithm = read_seq(digest_info)
  let hash_oid = read_oid(algorithm)
  let digest = read_tlv(digest_info)
  let salt = read_tlv(mac_info)
  let iterations = match mac_info.peek_tag() {
    Some(tag) => if tag == 0x02 { read_int(mac_info) } else { 1 }
    None => 1
  }
  let hash = hash_of_oid(hash_oid)
  let key_length = @crypto.digest(hash, Bytes::from_array([])).length()
  let mut matched = false
  for candidate in [password_bmp, password_utf8] {
    let key = pkcs12_kdf(
      hash,
      candidate,
      salt.content,
      3,
      iterations,
      key_length,
    )
    let computed = match hash {
      @crypto.Hash::Sha1 => @crypto.hmac_sha1(key, auth_bytes)
      _ => @crypto.hmac_sha256(key, auth_bytes)
    }
    if @der.der_bytes_compare(computed, digest.content) == 0 {
      matched = true
    }
  }
  if !matched {
    raise Pkcs12Error::BadPassword
  }
}

///|
fn parse_safe_contents(
  bytes : Bytes,
  password_utf8 : Bytes,
  password_bmp : Bytes,
  certificates : Array[@x509.Certificate],
  private_key : Ref[Bytes?],
) -> Unit raise Pkcs12Error {
  let reader = reader_at(bytes)
  let safe_contents = read_seq(reader)
  while !safe_contents.is_empty() {
    let bag = read_seq(safe_contents)
    let bag_id = read_oid(bag)
    let wrapper = read_tlv(bag)
    if wrapper.tag != 0xA0 {
      raise Pkcs12Error::BadStructure("bag value is not [0] EXPLICIT")
    }
    let value_reader = reader_at(wrapper.content)
    let value = read_tlv(value_reader)
    if bag_id == @oids.pkcs12_cert_bag {
      let cert_bag = read_seq(reader_at(value.raw))
      let cert_type = read_oid(cert_bag)
      if cert_type != @oids.pkcs12_x509_certificate {
        continue
      }
      let cert_wrapper = read_tlv(cert_bag)
      let cert_inner = reader_at(cert_wrapper.content)
      let cert_octets = read_tlv(cert_inner)
      let cert = @x509.parse_certificate(cert_octets.content) catch {
        e => raise Pkcs12Error::X509(e)
      }
      certificates.push(cert)
    } else if bag_id == @oids.pkcs12_key_bag {
      private_key.val = Some(value.raw)
    } else if bag_id == @oids.pkcs12_shrouded_key_bag {
      let info = read_seq(reader_at(value.raw))
      let algorithm = read_tlv(info)
      let encrypted = read_tlv(info)
      let decrypted = decrypt_pbes2(
        reader_at(algorithm.raw),
        encrypted.content,
        password_utf8,
        password_bmp,
      )
      private_key.val = Some(decrypted)
    }
  }
}

///|
/// Parse a DER-encoded PKCS#12 file.
///
/// Supports PBES2 with PBKDF2 (HMAC-SHA1/SHA256) and AES-CBC, plus SHA-1 and
/// SHA-256 MACs. Legacy RC2/3DES files are rejected with a clear error.
pub fn parse_pkcs12(
  bytes : Bytes,
  password : String,
) -> Pkcs12 raise Pkcs12Error {
  let reader = reader_at(bytes)
  let pfx = read_seq(reader)
  let version = read_int(pfx)
  if version != 3 {
    raise Pkcs12Error::Unsupported("PKCS#12 version " + version.to_string())
  }
  let auth_info = read_seq(pfx)
  let auth_type = read_oid(auth_info)
  if auth_type != @oids.pkcs7_data {
    raise Pkcs12Error::BadStructure("authSafe is not data")
  }
  let auth_wrapper = read_tlv(auth_info)
  let auth_inner = reader_at(auth_wrapper.content)
  let auth_octets = read_tlv(auth_inner)
  let auth_bytes = auth_octets.content
  let password_bmp = bmp_password(password)
  let password_utf8 = @utf8.encode(password)
  if !pfx.is_empty() {
    verify_mac(pfx, auth_bytes, password_bmp, password_utf8)
  }
  let certificates : Array[@x509.Certificate] = []
  let private_key : Ref[Bytes?] = Ref(None)
  let auth_reader = reader_at(auth_bytes)
  let authenticated_safe = read_seq(auth_reader)
  while !authenticated_safe.is_empty() {
    let content_info = read_seq(authenticated_safe)
    let content_type = read_oid(content_info)
    let wrapper = read_tlv(content_info)
    let inner = reader_at(wrapper.content)
    if content_type == @oids.pkcs7_data {
      let octets = read_tlv(inner)
      parse_safe_contents(
        octets.content,
        password_utf8,
        password_bmp,
        certificates,
        private_key,
      )
    } else if content_type == @oids.pkcs7_encrypted_data {
      let encrypted = read_tlv(inner)
      let decrypted = decrypt_encrypted_data(
        encrypted.raw,
        password_utf8,
        password_bmp,
      )
      parse_safe_contents(
        decrypted, password_utf8, password_bmp, certificates, private_key,
      )
    }
  }
  { certificates, private_key_der: private_key.val, }
}

///|
/// Human-readable description of a PKCS#12 error.
pub fn Pkcs12Error::message(self : Pkcs12Error) -> String {
  match self {
    Der(detail) => "DER error: \{detail.message()}"
    X509(detail) => "certificate error: \{detail.message()}"
    BadPassword => "wrong PKCS#12 password (or unsupported MAC)"
    BadStructure(detail) => "bad PKCS#12 structure: \{detail}"
    Unsupported(detail) => "unsupported PKCS#12 feature: \{detail}"
  }
}

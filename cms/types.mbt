///|
/// Errors raised while building or parsing CMS structures.
pub(all) suberror CmsError {
  Der(@der.DerError)
  X509(@x509.X509Error)
  Crypto(@crypto.CryptoError)
  NotSignedData
  MissingField(String)
  UnsupportedVersion(Int32)
  UnsupportedDigest(String)
  UnsupportedSignature(String)
  NoSigner
  DigestMismatch
  SignatureInvalid
  Malformed(String)
}

///|
/// An AlgorithmIdentifier: OID plus optional raw parameters TLV.
pub(all) struct AlgorithmIdentifier {
  oid : String
  params_raw : Bytes?
}

///|
/// A CMS Attribute: type OID plus one or more DER-encoded values.
pub(all) struct Attribute {
  oid : String
  values : Array[Bytes]
}

///|
/// A parsed SignerInfo.
pub(all) struct SignerInfo {
  version : Int32
  issuer_raw : Bytes
  serial_raw : Bytes
  digest_oid : String
  /// The `[0] IMPLICIT` signed attributes exactly as they appear in the file.
  signed_attrs_raw : Bytes
  signed_attrs : Array[Attribute]
  signature_oid : String
  signature : Bytes
  unsigned_attrs_raw : Bytes?
}

///|
/// A parsed SignedData structure (detached or attached).
pub(all) struct SignedData {
  version : Int32
  content_type : String
  econtent : Bytes?
  certificates : Array[Bytes]
  signer_infos : Array[SignerInfo]
}

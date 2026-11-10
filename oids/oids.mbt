// OBJECT IDENTIFIER constants used by CMS, X.509 and PAdES.
//
// Strings are kept for comparisons and diagnostics; `encode` turns them into
// DER TLV bytes for assembly.

///|
/// id-data (1.2.840.113549.1.7.1)
pub let id_data : String = "1.2.840.113549.1.7.1"

///|
/// id-signedData (1.2.840.113549.1.7.2)
pub let id_signed_data : String = "1.2.840.113549.1.7.2"

///|
/// id-contentType (1.2.840.113549.1.9.3)
pub let id_content_type : String = "1.2.840.113549.1.9.3"

///|
/// id-messageDigest (1.2.840.113549.1.9.4)
pub let id_message_digest : String = "1.2.840.113549.1.9.4"

///|
/// id-signingTime (1.2.840.113549.1.9.5)
pub let id_signing_time : String = "1.2.840.113549.1.9.5"

///|
/// id-aa-signingCertificateV2 (1.2.840.113549.1.9.16.2.47)
pub let id_signing_certificate_v2 : String = "1.2.840.113549.1.9.16.2.47"

///|
/// SHA-1 (1.3.14.3.2.26)
pub let sha1 : String = "1.3.14.3.2.26"

///|
/// SHA-256 (2.16.840.1.101.3.4.2.1)
pub let sha256 : String = "2.16.840.1.101.3.4.2.1"

///|
/// SHA-384 (2.16.840.1.101.3.4.2.2)
pub let sha384 : String = "2.16.840.1.101.3.4.2.2"

///|
/// SHA-512 (2.16.840.1.101.3.4.2.3)
pub let sha512 : String = "2.16.840.1.101.3.4.2.3"

///|
/// rsaEncryption (1.2.840.113549.1.1.1)
pub let rsa_encryption : String = "1.2.840.113549.1.1.1"

///|
/// sha1WithRSAEncryption (1.2.840.113549.1.1.5)
pub let sha1_with_rsa : String = "1.2.840.113549.1.1.5"

///|
/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub let sha256_with_rsa : String = "1.2.840.113549.1.1.11"

///|
/// sha384WithRSAEncryption (1.2.840.113549.1.1.12)
pub let sha384_with_rsa : String = "1.2.840.113549.1.1.12"

///|
/// sha512WithRSAEncryption (1.2.840.113549.1.1.13)
pub let sha512_with_rsa : String = "1.2.840.113549.1.1.13"

///|
/// id-ecPublicKey (1.2.840.10045.2.1)
pub let ec_public_key : String = "1.2.840.10045.2.1"

///|
/// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
pub let ecdsa_with_sha256 : String = "1.2.840.10045.4.3.2"

///|
/// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
pub let ecdsa_with_sha384 : String = "1.2.840.10045.4.3.3"

///|
/// ecdsa-with-SHA512 (1.2.840.10045.4.3.4)
pub let ecdsa_with_sha512 : String = "1.2.840.10045.4.3.4"

///|
/// prime256v1 / secp256r1 (1.2.840.10045.3.1.7)
pub let curve_p256 : String = "1.2.840.10045.3.1.7"

///|
/// SM2 public key algorithm (1.2.156.10197.1.301)
pub let sm2 : String = "1.2.156.10197.1.301"

///|
/// SM3 digest (1.2.156.10197.1.401)
pub let sm3 : String = "1.2.156.10197.1.401"

///|
/// SM2-with-SM3 signature (1.2.156.10197.1.501)
pub let sm2_with_sm3 : String = "1.2.156.10197.1.501"

///|
/// Basic Constraints extension (2.5.29.19)
pub let basic_constraints : String = "2.5.29.19"

///|
/// Key Usage extension (2.5.29.15)
pub let key_usage : String = "2.5.29.15"

///|
/// Subject Key Identifier extension (2.5.29.14)
pub let subject_key_identifier : String = "2.5.29.14"

///|
/// Authority Key Identifier extension (2.5.29.35)
pub let authority_key_identifier : String = "2.5.29.35"

///|
/// Encode a dotted OID constant into a DER TLV.
///
/// Aborts on malformed constants: these are compile-time strings owned by this
/// package, so a failure is a programming error, not an input error.
pub fn encode(dotted : String) -> Bytes {
  @der.der_oid_parse(dotted) catch {
    _ => abort("invalid OID constant: \{dotted}")
  }
}

///|
/// id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
pub let id_ct_tst_info : String = "1.2.840.113549.1.9.16.1.4"

///|
/// id-aa-signatureTimeStampToken (1.2.840.113549.1.9.16.2.14)
pub let id_aa_signature_time_stamp : String = "1.2.840.113549.1.9.16.2.14"

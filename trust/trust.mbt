///|
/// Errors raised while building a certificate chain.
pub(all) suberror TrustError {
  X509(@x509.X509Error)
  NoCertificate
  IssuerNotFound
  NotACertificateAuthority
  PathLengthExceeded
  Expired
  NotYetValid
  SignatureInvalid
  Revoked
  LoopDetected
}

///|
/// A certificate path from the signer to a trust anchor.
pub(all) struct Chain {
  /// Leaf first, anchor last.
  certificates : Array[@x509.Certificate]
  /// True only when the last certificate is one of the supplied anchors.
  trusted : Bool
}

///|
fn ensure_valid(
  cert : @x509.Certificate,
  at_time : Int64,
) -> Unit raise TrustError {
  if at_time < cert.not_before {
    raise TrustError::NotYetValid
  }
  if at_time > cert.not_after {
    raise TrustError::Expired
  }
}

///|
fn is_anchor(
  cert : @x509.Certificate,
  anchors : Array[@x509.Certificate],
) -> Bool {
  for anchor in anchors {
    if @der.der_bytes_compare(cert.der, anchor.der) == 0 {
      return true
    }
  }
  false
}

///|
fn in_chain(chain : Array[@x509.Certificate], cert : @x509.Certificate) -> Bool {
  for item in chain {
    if @der.der_bytes_compare(item.der, cert.der) == 0 {
      return true
    }
  }
  false
}

///|
fn names_match(
  current : @x509.Certificate,
  candidate : @x509.Certificate,
) -> Bool {
  if @der.der_bytes_compare(current.issuer_raw, candidate.subject_raw) != 0 {
    return false
  }
  match (current.authority_key_id, candidate.subject_key_id) {
    (Some(aki), Some(ski)) =>
      if @der.der_bytes_compare(aki, ski) != 0 {
        return false
      }
    _ => ()
  }
  true
}

///|
/// Result of looking for the issuer of one certificate.
priv enum IssuerLookup {
  Found(@x509.Certificate, Bool)
  NameOnly
  Missing
}

///|
fn lookup_issuer(
  current : @x509.Certificate,
  intermediates : Array[@x509.Certificate],
  anchors : Array[@x509.Certificate],
  chain : Array[@x509.Certificate],
) -> IssuerLookup {
  let mut name_only = false
  // Prefer an anchor when it is the issuer: that ends the path early.
  for candidate in anchors {
    if names_match(current, candidate) {
      name_only = true
      if !in_chain(chain, candidate) &&
        @x509.verify_certificate_signature(current, candidate) {
        return IssuerLookup::Found(candidate, true)
      }
    }
  }
  for candidate in intermediates {
    if names_match(current, candidate) {
      name_only = true
      if !in_chain(chain, candidate) &&
        @x509.verify_certificate_signature(current, candidate) {
        return IssuerLookup::Found(candidate, false)
      }
    }
  }
  if name_only {
    IssuerLookup::NameOnly
  } else {
    IssuerLookup::Missing
  }
}

///|
fn count_ca_certificates(chain : Array[@x509.Certificate]) -> Int32 {
  let mut count = 0
  for i in 1..<chain.length() {
    if chain[i].is_ca {
      count = count + 1
    }
  }
  count
}

///|
fn check_revocations(
  chain : Array[@x509.Certificate],
  crls : Array[@x509.Crl],
  at_time : Int64,
) -> Unit raise TrustError {
  if crls.length() == 0 {
    return
  }
  for i in 0..<(chain.length() - 1) {
    let child = chain[i]
    let issuer = chain[i + 1]
    for crl in crls {
      if @der.der_bytes_compare(crl.issuer_raw, child.issuer_raw) != 0 {
        continue
      }
      if !@x509.verify_crl_signature(crl, issuer) {
        continue
      }
      if crl.this_update > at_time {
        continue
      }
      match crl.next_update {
        Some(next) => if next < at_time { continue }
        None => ()
      }
      if crl.is_revoked(child.serial_raw) {
        raise TrustError::Revoked
      }
    }
  }
}

///|
/// Build and verify a chain from `leaf` to one of `anchors`.
///
/// Checks signature links, validity at `at_time`, CA basic constraints, key
/// usage (when present) and path length constraints.
pub fn build_chain(
  leaf : @x509.Certificate,
  intermediates : Array[@x509.Certificate],
  anchors : Array[@x509.Certificate],
  at_time : Int64,
) -> Chain raise TrustError {
  build_chain_with_crls(leaf, intermediates, anchors, [], at_time)
}

///|
/// Same as `build_chain`, but also checks revocation against `crls`.
pub fn build_chain_with_crls(
  leaf : @x509.Certificate,
  intermediates : Array[@x509.Certificate],
  anchors : Array[@x509.Certificate],
  crls : Array[@x509.Crl],
  at_time : Int64,
) -> Chain raise TrustError {
  ensure_valid(leaf, at_time)
  let chain : Array[@x509.Certificate] = [leaf]
  if is_anchor(leaf, anchors) {
    return { certificates: chain, trusted: true, }
  }
  let mut current = leaf
  let mut depth = 0
  while depth < 8 {
    let lookup = lookup_issuer(current, intermediates, anchors, chain)
    match lookup {
      Found(issuer, is_trust_anchor) => {
        ensure_valid(issuer, at_time)
        if is_trust_anchor {
          chain.push(issuer)
          check_revocations(chain, crls, at_time)
          return { certificates: chain, trusted: true, }
        }
        if !issuer.is_ca {
          raise TrustError::NotACertificateAuthority
        }
        if issuer.has_key_usage && !issuer.key_cert_sign {
          raise TrustError::NotACertificateAuthority
        }
        match issuer.path_len {
          Some(limit) =>
            if count_ca_certificates(chain) > limit {
              raise TrustError::PathLengthExceeded
            }
          None => ()
        }
        chain.push(issuer)
        current = issuer
        depth = depth + 1
      }
      NameOnly => raise TrustError::SignatureInvalid
      Missing => raise TrustError::IssuerNotFound
    }
  }
  raise TrustError::LoopDetected
}

///|
/// Human-readable description of a trust error.
pub fn TrustError::message(self : TrustError) -> String {
  match self {
    X509(detail) => "certificate error: \{detail.message()}"
    NoCertificate => "no certificate"
    IssuerNotFound => "could not find the issuer certificate"
    NotACertificateAuthority => "issuer is not a certificate authority"
    PathLengthExceeded => "certificate path length constraint exceeded"
    Expired => "certificate has expired"
    NotYetValid => "certificate is not valid yet"
    SignatureInvalid => "certificate signature does not verify"
    Revoked => "certificate has been revoked"
    LoopDetected => "certificate chain loops"
  }
}

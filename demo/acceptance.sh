#!/usr/bin/env bash
# One-command acceptance demo. Runs the main flows and prints a pass/fail table.
# Usage: bash demo/acceptance.sh
# Optional: MOON_TARGET=wasm-gc bash demo/acceptance.sh
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
log="$work/last.log"

moon_run() {
  if [ -n "${MOON_TARGET:-}" ]; then
    moon run --target "$MOON_TARGET" "$@"
  else
    moon run "$@"
  fi
}

pass=0
fail=0

ok() {
  printf '[PASS] %s\n' "$1"
  pass=$((pass + 1))
}

no() {
  printf '[FAIL] %s\n' "$1"
  if [ -f "$log" ]; then
    sed 's/^/       /' "$log" | tail -n 6
  fi
  fail=$((fail + 1))
}

# 1. Generate a realistic two-page PDF.
if moon_run cmd/mkpdf -- "$work/rich.pdf" --rich --pages 2 >"$log" 2>&1; then
  ok "generate a two-page PDF with text and links"
else
  no "generate a two-page PDF with text and links"
fi

# 2. Sign page 2 with a visible signature.
if moon_run cmd/moonsign -- sign "$work/rich.pdf" --out "$work/signed.pdf" \
  --key testdata/certs/rsa.key --cert testdata/certs/rsa.crt \
  --visible --page 2 --rect 36,600,336,664 >"$log" 2>&1; then
  ok "sign page 2 with a visible signature"
else
  no "sign page 2 with a visible signature"
fi

# 3. Verify: valid, and the signer name is shown.
if moon_run cmd/moonsign -- verify "$work/signed.pdf" --cert testdata/certs/rsa.crt >"$log" 2>&1 &&
  grep -q "Result: VALID" "$log" && grep -q "signer:" "$log"; then
  ok "verify a valid signature (shows signer)"
else
  no "verify a valid signature (shows signer)"
fi

# 4. Tamper with one byte: must exit 2.
printf 'X' | dd of="$work/signed.pdf" bs=1 seek=10 count=1 conv=notrunc 2>/dev/null
moon_run cmd/moonsign -- verify "$work/signed.pdf" --cert testdata/certs/rsa.crt >"$log" 2>&1
code=$?
if [ "$code" -eq 2 ] && grep -q "Result: INVALID" "$log"; then
  ok "reject a tampered file (exit 2)"
else
  no "reject a tampered file (exit 2)"
fi

# 5. Append a second signature: both stay valid.
if moon_run cmd/moonsign -- sign "$work/rich.pdf" --out "$work/twice.pdf" \
  --key testdata/certs/rsa.key --cert testdata/certs/rsa.crt >"$log" 2>&1 &&
  moon_run cmd/moonsign -- sign "$work/twice.pdf" --out "$work/twice2.pdf" \
    --key testdata/certs/rsa.key --cert testdata/certs/rsa.crt >"$log" 2>&1 &&
  moon_run cmd/moonsign -- verify "$work/twice2.pdf" --cert testdata/certs/rsa.crt >"$log" 2>&1 &&
  [ "$(grep -c "Result: VALID" "$log")" -eq 2 ]; then
  ok "append a second signature (both valid)"
else
  no "append a second signature (both valid)"
fi

# 6. DSS supplies the intermediate certificate: chain becomes trusted.
if moon_run cmd/moonsign -- sign "$work/rich.pdf" --out "$work/leaf.pdf" \
  --key testdata/certs/leaf.key --cert testdata/certs/leaf.crt >"$log" 2>&1 &&
  moon_run cmd/moonsign -- dss "$work/leaf.pdf" --cert testdata/certs/int.crt \
    --out "$work/leaf-dss.pdf" >"$log" 2>&1 &&
  moon_run cmd/moonsign -- verify "$work/leaf-dss.pdf" \
    --anchors testdata/certs/ca.crt >"$log" 2>&1 &&
  grep -q "VALID and TRUSTED" "$log"; then
  ok "complete the chain from DSS (trusted)"
else
  no "complete the chain from DSS (trusted)"
fi

# 7. DSS supplies a CRL that revokes the signer: must exit 3.
moon_run cmd/moonsign -- dss "$work/leaf.pdf" --cert testdata/certs/int.crt \
  --crl testdata/certs/crl.pem --out "$work/leaf-revoked.pdf" >"$log" 2>&1
moon_run cmd/moonsign -- verify "$work/leaf-revoked.pdf" \
  --anchors testdata/certs/ca.crt >"$log" 2>&1
code=$?
if [ "$code" -eq 3 ] && grep -q "revoked" "$log"; then
  ok "reject a revoked certificate from DSS (exit 3)"
else
  no "reject a revoked certificate from DSS (exit 3)"
fi

# 8. Encrypted PDF input.
if moon_run cmd/mkpdf -- "$work/enc.pdf" --rich --pages 2 --encrypt secret >"$log" 2>&1 &&
  moon_run cmd/moonsign -- sign "$work/enc.pdf" --out "$work/enc-signed.pdf" \
    --key testdata/certs/rsa.key --cert testdata/certs/rsa.crt \
    --pdf-password secret >"$log" 2>&1 &&
  moon_run cmd/moonsign -- verify "$work/enc-signed.pdf" --cert testdata/certs/rsa.crt >"$log" 2>&1 &&
  grep -q "Result: VALID" "$log"; then
  ok "sign an encrypted PDF, then verify"
else
  no "sign an encrypted PDF, then verify"
fi

# 9. SM2 / SM3.
if moon_run cmd/moonsign -- sign "$work/rich.pdf" --out "$work/sm2.pdf" \
  --key testdata/certs/sm2.key --cert testdata/certs/sm2.crt >"$log" 2>&1 &&
  moon_run cmd/moonsign -- verify "$work/sm2.pdf" --cert testdata/certs/sm2.crt >"$log" 2>&1 &&
  grep -q "Result: VALID" "$log"; then
  ok "SM2/SM3 sign and verify"
else
  no "SM2/SM3 sign and verify"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
  exit 1
fi

#!/usr/bin/env bash
# End-to-end demo: visible signature, append, verify all, DSS, tamper check.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== create a two-page PDF with text and link annotations =="
moon run cmd/mkpdf -- "$work/rich.pdf" --rich --pages 2

openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" \
  -days 365 -nodes -subj "/CN=MoonSign Demo" >/dev/null 2>&1

echo "== sign page 2 with a visible signature =="
moon run cmd/moonsign -- sign "$work/rich.pdf" --out "$work/signed.pdf" \
  --key "$work/key.pem" --cert "$work/cert.pem" --visible --page 2

echo "== verify (shows signer and signing time) =="
moon run cmd/moonsign -- verify "$work/signed.pdf" --cert "$work/cert.pem"

echo "== append a second signature =="
moon run cmd/moonsign -- sign "$work/signed.pdf" --out "$work/twice.pdf" \
  --key "$work/key.pem" --cert "$work/cert.pem"

echo "== verify both signatures =="
moon run cmd/moonsign -- verify "$work/twice.pdf" --cert "$work/cert.pem"

echo "== embed the certificate in a DSS =="
moon run cmd/moonsign -- dss "$work/twice.pdf" --cert "$work/cert.pem" \
  --out "$work/with-dss.pdf"
moon run cmd/moonsign -- verify "$work/with-dss.pdf" --cert "$work/cert.pem"

echo "== tamper with one byte (expected: INVALID, exit 2) =="
python3 - "$work/signed.pdf" "$work/tampered.pdf" <<'PY'
import sys

source, target = sys.argv[1], sys.argv[2]
data = bytearray(open(source, "rb").read())
data[10] ^= 0x01
open(target, "wb").write(data)
PY

set +e
moon run cmd/moonsign -- verify "$work/tampered.pdf" --cert "$work/cert.pem"
code=$?
set -e
if [ "$code" -ne 2 ]; then
  echo "expected exit code 2 for the tampered file, got $code" >&2
  exit 1
fi

echo "== full demo passed =="

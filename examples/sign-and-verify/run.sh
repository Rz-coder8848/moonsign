#!/usr/bin/env bash
# Sign a PDF, verify it, then tamper with it and check that verification fails.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== create a blank PDF and a throwaway certificate =="
moon run cmd/mkpdf -- "$work/blank.pdf"

openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" \
  -days 365 -nodes -subj "/CN=MoonSign Example" >/dev/null 2>&1

echo "== sign =="
moon run cmd/moonsign -- sign "$work/blank.pdf" \
  --key "$work/key.pem" --cert "$work/cert.pem" --out "$work/signed.pdf"

echo "== verify (expected: VALID) =="
moon run cmd/moonsign -- verify "$work/signed.pdf" --cert "$work/cert.pem"

echo "== info =="
moon run cmd/moonsign -- info "$work/signed.pdf"

echo "== tamper with one byte =="
python3 - "$work/signed.pdf" "$work/tampered.pdf" <<'PY'
import sys

source, target = sys.argv[1], sys.argv[2]
data = bytearray(open(source, "rb").read())
# The first bytes of the file are covered by the signature.
data[10] ^= 0x01
open(target, "wb").write(data)
print(f"flipped one byte and wrote {target}")
PY

set +e
moon run cmd/moonsign -- verify "$work/tampered.pdf" --cert "$work/cert.pem"
code=$?
set -e

if [ "$code" -ne 2 ]; then
  echo "expected exit code 2 for the tampered file, got $code" >&2
  exit 1
fi

echo "== example passed =="

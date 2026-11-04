#!/usr/bin/env python3
"""Verify the signature embedded in a PDF using OpenSSL CMS.

This is an interoperability check for MoonSign: it extracts the detached CMS
signature and the bytes covered by /ByteRange, then asks `openssl cms -verify`
to validate them. It does not validate certificate trust (`-noverify`).

Usage:
    python scripts/verify_pdf_signature.py signed.pdf
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def openssl_bin() -> str:
    candidate = os.environ.get("OPENSSL_BIN")
    if candidate and Path(candidate).exists():
        return candidate
    for name in ("openssl.exe", "openssl"):
        found = __import__("shutil").which(name)
        if found:
            return found
    raise SystemExit("openssl not found; set OPENSSL_BIN")


def der_total_length(data: bytes) -> int:
    if len(data) < 2 or data[0] != 0x30:
        raise SystemExit("CMS does not start with a DER SEQUENCE")
    first = data[1]
    if first < 0x80:
        return 2 + first
    count = first & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count:
        raise SystemExit("bad DER length")
    value = int.from_bytes(data[2 : 2 + count], "big")
    return 2 + count + value


def parse_byte_range(pdf: bytes) -> tuple[int, int, int, int]:
    match = re.search(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", pdf)
    if not match:
        raise SystemExit("no /ByteRange found")
    return tuple(int(group) for group in match.groups())  # type: ignore[return-value]


def parse_contents(pdf: bytes, after: int) -> tuple[bytes, int, int]:
    match = re.search(rb"/Contents\s*<([0-9A-Fa-f\s]+)>", pdf[after:])
    if not match:
        raise SystemExit("no /Contents hex string found")
    start = after + match.start(1)
    end = after + match.end(1)
    hex_text = re.sub(rb"\s+", b"", match.group(1))
    return bytes.fromhex(hex_text.decode("ascii")), start, end


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_pdf_signature.py signed.pdf")
    pdf_path = Path(sys.argv[1])
    pdf = pdf_path.read_bytes()

    first_len, second_start, second_len = 0, 0, 0
    a, b, c, d = parse_byte_range(pdf)
    if a != 0 or b <= 0:
        raise SystemExit("unexpected ByteRange start")
    first_len, second_start, second_len = b, c, d

    cms_padded, contents_start, contents_end = parse_contents(pdf, 0)
    if contents_start - 1 != first_len:
        raise SystemExit(
            f"/Contents starts at {contents_start - 1}, ByteRange ends at {first_len}"
        )
    if contents_end + 1 != second_start:
        raise SystemExit(
            f"/Contents ends at {contents_end + 1}, second range starts at {second_start}"
        )
    if second_start + second_len != len(pdf):
        raise SystemExit("second ByteRange does not reach the end of the file")

    cms_length = der_total_length(cms_padded)
    cms = cms_padded[:cms_length]

    content = pdf[0:first_len] + pdf[second_start : second_start + second_len]

    with tempfile.TemporaryDirectory() as tmp:
        cms_path = Path(tmp) / "signature.der"
        content_path = Path(tmp) / "content.bin"
        cms_path.write_bytes(cms)
        content_path.write_bytes(content)
        result = subprocess.run(
            [
                openssl_bin(),
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                str(cms_path),
                "-content",
                str(content_path),
                "-noverify",
                "-out",
                os.devnull,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return 1
    print(
        f"OK: CMS {cms_length} bytes, covered {first_len + second_len} of {len(pdf)} bytes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

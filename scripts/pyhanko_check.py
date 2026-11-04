#!/usr/bin/env python3
"""Cross-check MoonSign against pyHanko, an independent PAdES implementation.

Two modes:

    pyhanko_check.py validate signed.pdf
        Check that the first embedded signature is cryptographically intact
        (digest + signature). Trust is not evaluated.

    pyhanko_check.py sign input.pdf output.pdf key.pem cert.pem
        Sign a PDF with pyHanko (incremental update), so MoonSign can verify a
        signature produced by a different implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path


def validate(path: str) -> int:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    with open(path, "rb") as handle:
        reader = PdfFileReader(handle)
        signatures = reader.embedded_signatures
        if not signatures:
            print("no embedded signature", file=sys.stderr)
            return 1
        status = validate_pdf_signature(signatures[0])
        print(status.summary())
        if not status.intact:
            print("signature is not intact", file=sys.stderr)
            return 1
    print("OK: pyHanko reports the signature is intact")
    return 0


def sign(source: str, output: str, key: str, cert: str) -> int:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import PdfSignatureMetadata, SimpleSigner
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.sign.signers.pdf_signer import PdfSigner

    signer = SimpleSigner.load(key, cert)
    metadata = PdfSignatureMetadata(field_name="Signature1", md_algorithm="sha256")
    field_spec = SigFieldSpec(sig_field_name="Signature1", box=(0, 0, 0, 0))
    with open(source, "rb") as infile:
        writer = IncrementalPdfFileWriter(infile)
        with open(output, "wb") as outfile:
            PdfSigner(
                metadata, signer=signer, new_field_spec=field_spec
            ).sign_pdf(writer, outfile)
    print(f"pyHanko signed {source} -> {output}")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "validate":
        return validate(args[1])
    if len(args) == 5 and args[0] == "sign":
        return sign(args[1], args[2], args[3], args[4])
    print(__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

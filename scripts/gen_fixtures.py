#!/usr/bin/env python3
"""Regenerate MoonSign test fixtures.

Requires OpenSSL 3.x on PATH (or set OPENSSL_BIN). The generated file contains
only public test material and throwaway private keys; never use these keys for
anything real.

Usage:
    python scripts/gen_fixtures.py
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "testdata" / "certs"
OUT = ROOT / "testdata" / "fixtures.mbt"


def openssl_bin() -> str:
    candidate = os.environ.get("OPENSSL_BIN")
    if candidate and Path(candidate).exists():
        return candidate
    for name in ("openssl.exe", "openssl"):
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit("openssl not found; set OPENSSL_BIN")


def run(args: list[str]) -> str:
    result = subprocess.run(
        [openssl_bin(), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def grab_block(text: str, label: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == label + ":":
            parts: list[str] = []
            for follow in lines[i + 1 :]:
                stripped = follow.strip()
                if not stripped:
                    break
                if not re.fullmatch(r"[0-9a-fA-F:]+", stripped):
                    break
                parts.append(stripped.replace(":", ""))
            return "".join(parts)
    raise SystemExit(f"block {label!r} not found")


def rsa_numbers(key: Path) -> tuple[str, str, str]:
    text = run(["pkey", "-in", str(key), "-text", "-noout"])
    modulus = grab_block(text, "modulus")
    private_exponent = grab_block(text, "privateExponent")
    match = re.search(r"publicExponent:\s+\d+\s+\(0x([0-9a-fA-F]+)\)", text)
    if not match:
        raise SystemExit("public exponent not found")
    return modulus, match.group(1), private_exponent


def ec_numbers(key: Path) -> str:
    text = run(["pkey", "-in", str(key), "-text", "-noout"])
    return grab_block(text, "priv")


def der_hex(path: Path) -> str:
    return path.read_bytes().hex()


def even_hex(value: str) -> str:
    return value if len(value) % 2 == 0 else '0' + value


def ensure_chain() -> None:
    """Generate a root -> intermediate -> leaf RSA chain if it is missing."""
    if (CERTS / "ca.der").exists() and (CERTS / "int.der").exists() and (
        CERTS / "leaf.der"
    ).exists():
        return
    run(
        [
            "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(CERTS / "ca.key"),
            "-out", str(CERTS / "ca.crt"), "-days", "3650", "-nodes",
            "-subj", "/CN=MoonSign Test Root CA/O=MoonSign",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-sha256",
        ]
    )
    run(
        [
            "req", "-newkey", "rsa:2048", "-keyout", str(CERTS / "int.key"),
            "-out", str(CERTS / "int.csr"), "-nodes",
            "-subj", "/CN=MoonSign Test Intermediate/O=MoonSign",
        ]
    )
    (CERTS / "int.ext").write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n",
        encoding="utf-8",
    )
    run(
        [
            "x509", "-req", "-in", str(CERTS / "int.csr"),
            "-CA", str(CERTS / "ca.crt"), "-CAkey", str(CERTS / "ca.key"),
            "-CAcreateserial", "-out", str(CERTS / "int.crt"),
            "-days", "3000", "-sha256", "-extfile", str(CERTS / "int.ext"),
        ]
    )
    run(
        [
            "req", "-newkey", "rsa:2048", "-keyout", str(CERTS / "leaf.key"),
            "-out", str(CERTS / "leaf.csr"), "-nodes",
            "-subj", "/CN=MoonSign Test Leaf/O=MoonSign",
        ]
    )
    (CERTS / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,nonRepudiation\n",
        encoding="utf-8",
    )
    run(
        [
            "x509", "-req", "-in", str(CERTS / "leaf.csr"),
            "-CA", str(CERTS / "int.crt"), "-CAkey", str(CERTS / "int.key"),
            "-CAcreateserial", "-out", str(CERTS / "leaf.crt"),
            "-days", "2000", "-sha256", "-extfile", str(CERTS / "leaf.ext"),
        ]
    )
    for name in ("ca", "int", "leaf"):
        run(
            [
                "x509", "-in", str(CERTS / f"{name}.crt"), "-outform", "DER",
                "-out", str(CERTS / f"{name}.der"),
            ]
        )


def main() -> None:
    CERTS.mkdir(parents=True, exist_ok=True)
    ensure_chain()
    message = b"MoonSign interoperability test vector\n"
    message_path = CERTS / "message.bin"
    message_path.write_bytes(message)

    rsa_n, rsa_e, rsa_d = rsa_numbers(CERTS / "rsa.key")
    ec_priv = ec_numbers(CERTS / "ec.key")

    cms_path = CERTS / "openssl-cms-detached.der"
    if cms_path.exists():
        cms_path.unlink()
    run(
        [
            "cms",
            "-sign",
            "-binary",
            "-md",
            "sha256",
            "-in",
            str(message_path),
            "-signer",
            str(CERTS / "rsa.crt"),
            "-inkey",
            str(CERTS / "rsa.key"),
            "-outform",
            "DER",
            "-out",
            str(cms_path),
        ]
    )

    rsa_key_der = CERTS / "rsa.key.der"
    ec_key_der = CERTS / "ec.key.der"
    leaf_key_der = CERTS / "leaf.key.der"
    run(["pkcs8", "-topk8", "-nocrypt", "-in", str(CERTS / "leaf.key"), "-outform", "DER", "-out", str(leaf_key_der)])
    run(["pkcs8", "-topk8", "-nocrypt", "-in", str(CERTS / "rsa.key"), "-outform", "DER", "-out", str(rsa_key_der)])
    run(["pkcs8", "-topk8", "-nocrypt", "-in", str(CERTS / "ec.key"), "-outform", "DER", "-out", str(ec_key_der)])

    digest = hashlib.sha256(message).hexdigest()
    lines = [
        "// Generated by scripts/gen_fixtures.py. Do not edit by hand.",
        "//",
        "// Test-only material: the private keys are throwaway and are never used",
        "// outside this repository.",
        "",
        f'pub let rsa_cert_der_hex : String = "{der_hex(CERTS / "rsa.der")}"',
        "",
        f'pub let rsa_n_hex : String = "{rsa_n}"',
        "",
        f'pub let rsa_e_hex : String = "{even_hex(rsa_e)}"',
        "",
        f'pub let rsa_d_hex : String = "{rsa_d}"',
        "",
        f'pub let ec_cert_der_hex : String = "{der_hex(CERTS / "ec.der")}"',
        "",
        f'pub let ec_priv_hex : String = "{even_hex(ec_priv)}"',
        "",
        f'pub let fixture_message_hex : String = "{message.hex()}"',
        "",
        f'pub let fixture_message_sha256_hex : String = "{digest}"',
        "",
        f'pub let openssl_cms_detached_hex : String = "{der_hex(cms_path)}"',
        "",
        f'pub let rsa_key_der_hex : String = "{der_hex(rsa_key_der)}"',
        "",
        f'pub let ec_key_der_hex : String = "{der_hex(ec_key_der)}"',
        "",
        f'pub let chain_root_der_hex : String = "{der_hex(CERTS / "ca.der")}"',
        "",
        f'pub let chain_intermediate_der_hex : String = "{der_hex(CERTS / "int.der")}"',
        "",
        f'pub let chain_leaf_der_hex : String = "{der_hex(CERTS / "leaf.der")}"',
        "",
        f'pub let chain_leaf_key_der_hex : String = "{der_hex(leaf_key_der)}"',
        "",
        f'pub let crl_der_hex : String = "{der_hex(CERTS / "crl.der")}"',
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    sys.exit(main())

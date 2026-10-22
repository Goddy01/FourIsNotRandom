#!/usr/bin/env python3
"""Generate a demo PEM and a hash list that matches it (FAIL) plus a clean PEM (PASS)."""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
CERTS = HERE / "certs"


def make_cert(cn: str) -> tuple[x509.Certificate, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, pem


def main() -> None:
    CERTS.mkdir(parents=True, exist_ok=True)
    bad, bad_pem = make_cert("demo-compromised-intermediate.local")
    good, good_pem = make_cert("demo-clean-ca.local")

    (CERTS / "demo-bad.pem").write_bytes(bad_pem)
    (CERTS / "demo-clean.pem").write_bytes(good_pem)

    der = bad.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()

    hashes = {
        "source": "demo only — not a real eMudhra cert; used to exercise FAIL matching",
        "certificates": [
            {
                "name": "DEMO Intermediate (synthetic)",
                "ccadb": "DEMO",
                "issuer": "demo",
                "sha256": fp,
            }
        ],
    }
    (CERTS / "demo-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {CERTS / 'demo-bad.pem'} (fingerprint {fp})")
    print(f"Wrote {CERTS / 'demo-clean.pem'}")
    print(f"Wrote {CERTS / 'demo-hashes.json'}")


if __name__ == "__main__":
    main()

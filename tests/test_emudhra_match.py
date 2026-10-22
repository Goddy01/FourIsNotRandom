import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fourisnotrandom.checks.emudhra import cert_digests, scan_certificates
from fourisnotrandom.models import Status
from fourisnotrandom.versioning import any_hash_match


def _self_signed() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_dual_digest_match_on_cert_fingerprint():
    cert = _self_signed()
    cert_fp, spki_fp = cert_digests(cert)
    assert len(cert_fp) == 64
    assert len(spki_fp) == 64
    assert cert_fp != spki_fp

    # Match via full-cert hash (Talos-style list)
    findings = scan_certificates([cert], target="test", hashes={cert_fp})
    assert any(f.status == Status.FAIL for f in findings)

    # Match via SPKI hash (Go-style list)
    findings = scan_certificates([cert], target="test", hashes={spki_fp})
    assert any(f.status == Status.FAIL for f in findings)

    # No match
    findings = scan_certificates([cert], target="test", hashes={"0" * 64})
    assert findings[0].status == Status.PASS


def test_any_hash_match_normalizes():
    h = hashlib.sha256(b"x").hexdigest()
    assert any_hash_match([h.upper()], [h]) == h

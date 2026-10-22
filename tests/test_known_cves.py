"""Regression suite for the 16-item correctness checklist.

Keeps advisory verdicts, labels, and safety rails from silently drifting
when floors, hash lists, or comparison helpers change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fourisnotrandom.checks import emudhra as emudhra_checks
from fourisnotrandom.checks import gitlab as gitlab_checks
from fourisnotrandom.checks import litellm as litellm_checks
from fourisnotrandom.checks import php as php_checks
from fourisnotrandom.config_loader import compromised_hash_set, load_fixed_versions
from fourisnotrandom.models import Status
from fourisnotrandom.targets import TargetError, assert_not_cidr_or_range
from fourisnotrandom.versioning import gitlab_exposure, php_exposure


FIXED = load_fixed_versions()
PHP_FLOORS = FIXED["php"]["fixed_by_branch"]
GL = FIXED["gitlab"]["cves"]
CVE_110264 = GL["CVE-2026-110264"]
CVE_97229 = GL["CVE-2026-97229"]


# --- Item 1: PHP version floors ---


@pytest.mark.parametrize(
    "version,expected",
    [
        ("8.2.34", "FAIL"),
        ("8.2.35", "PASS"),
        ("8.3.35", "FAIL"),
        ("8.3.36", "PASS"),
        ("8.4.26", "FAIL"),
        ("8.4.27", "PASS"),
        ("8.5.11", "FAIL"),
        ("8.5.12", "PASS"),
        ("8.4.27.1", "PASS"),
    ],
)
def test_item1_php_floors(version: str, expected: str):
    status, _, reason = php_exposure(version, PHP_FLOORS)
    assert status == expected
    finding = php_checks.evaluate_php_version(version, FIXED["php"])
    assert finding.status.value == expected
    assert finding.detection_method


def test_item1_php_eol_distinct_message():
    status, _, reason = php_exposure("8.1.30", PHP_FLOORS)
    assert status == "FAIL"
    assert reason == "eol_no_fix"
    finding = php_checks.evaluate_php_version("8.1.30", FIXED["php"])
    assert "No fix available, major upgrade required" in finding.remediation


# --- Item 2: unparseable ---


@pytest.mark.parametrize("version", ["notaversion", "", None])
def test_item2_php_unparseable_unknown(version):
    finding = php_checks.evaluate_php_version(version, FIXED["php"])  # type: ignore[arg-type]
    assert finding.status == Status.UNKNOWN
    assert finding.detail == "unparseable"


# --- Item 3: detection_method labels ---


def test_item3_dockerfile_detection(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM php:8.2.34-cli\n", encoding="utf-8")
    findings = php_checks.check_filesystem(tmp_path, config=FIXED)
    assert any(
        f.detection_method == "detected via Dockerfile FROM line" and f.installed == "8.2.34"
        for f in findings
    )


def test_item3_composer_lock_detection(tmp_path: Path):
    (tmp_path / "composer.lock").write_text(
        json.dumps({"platform": {"php": "8.3.35"}, "packages": []}),
        encoding="utf-8",
    )
    findings = php_checks.check_filesystem(tmp_path, config=FIXED)
    assert any(
        f.detection_method == "detected via composer.lock" and f.installed == "8.3.35"
        for f in findings
    )


# --- Item 4: GitLab floors ---


@pytest.mark.parametrize(
    "version,cve,expected,reason",
    [
        ("19.4.2", "CVE-2026-110264", "FAIL", "below_fixed"),
        ("19.4.3", "CVE-2026-110264", "PASS", "at_or_above_fixed"),
        ("18.11.12", "CVE-2026-110264", "FAIL", "below_fixed"),
        ("18.11.13", "CVE-2026-110264", "PASS", "at_or_above_fixed"),
        ("19.5.0", "CVE-2026-110264", "FAIL", "below_fixed"),
        ("19.5.1", "CVE-2026-110264", "PASS", "at_or_above_fixed"),
        ("19.3.5-internal0", "CVE-2026-110264", "PASS", "dedicated_internal_build"),
        ("7.14.2", "CVE-2026-110264", "FAIL", "no_backport"),
        ("20.0.0", "CVE-2026-110264", "PASS", "newer_than_table"),
        # 97229 closed window - 19.5+/20.x are confirmed N/A, not beyond-table.
        ("19.5.0", "CVE-2026-97229", "PASS", "not_in_affected_range"),
        ("20.0.0", "CVE-2026-97229", "PASS", "not_in_affected_range"),
        ("19.4.2", "CVE-2026-97229", "PASS", "at_or_above_fixed"),
    ],
)
def test_item4_gitlab_verdicts(version: str, cve: str, expected: str, reason: str):
    meta = GL[cve]
    status, _, got_reason = gitlab_exposure(
        version,
        meta["fixed_by_branch"],
        meta.get("min_affected"),
        meta.get("max_affected"),
    )
    assert status == expected
    assert got_reason == reason


def test_item4_ancient_backport_message():
    findings = gitlab_checks.evaluate_gitlab_version("7.14.2", config=FIXED)
    fail = next(f for f in findings if f.cve == "CVE-2026-110264")
    assert fail.status == Status.FAIL
    assert "No backport available for this branch, full upgrade required" in fail.remediation


def test_item4_beyond_table_message_110264_only():
    findings = gitlab_checks.evaluate_gitlab_version("20.0.0", config=FIXED)
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2026-110264"].detail == "newer_than_table"
    assert "manually confirm" in by_cve["CVE-2026-110264"].remediation.lower()
    assert by_cve["CVE-2026-97229"].detail == "not_in_affected_range"
    assert "beyond" not in by_cve["CVE-2026-97229"].remediation.lower()


# --- Item 5: independent CVE tracking ---


def test_item5_oct12_vs_oct21_gap():
    findings = gitlab_checks.evaluate_gitlab_version("19.4.2", config=FIXED)
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2026-97229"].status == Status.PASS
    assert by_cve["CVE-2026-110264"].status == Status.FAIL


# --- Items 6-8: eMudhra hash matching ---


def test_item6_dual_digest_match_types(tmp_path: Path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EM DV TLS CA - G3B")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_fp, spki_fp = emudhra_checks.cert_digests(cert)
    pem = tmp_path / "em.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Talos-style fingerprint for EM DV is present in the bundled list.
    bundled = compromised_hash_set()
    assert "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493" in bundled

    fail_cert = emudhra_checks.scan_certificates([cert], target=str(pem), hashes={cert_fp})
    assert fail_cert[0].status == Status.FAIL
    assert fail_cert[0].extra["matched_via"] == "full-certificate SHA-256"

    fail_spki = emudhra_checks.scan_certificates([cert], target=str(pem), hashes={spki_fp})
    assert fail_spki[0].status == Status.FAIL
    assert fail_spki[0].extra["matched_via"] == "SPKI SHA-256"


def test_item7_clean_cert_passes(tmp_path: Path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "clean-ca.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = tmp_path / "clean.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    findings = emudhra_checks.check_path(pem, hashes=compromised_hash_set())
    assert all(f.status != Status.FAIL for f in findings)
    assert any(f.status == Status.PASS for f in findings)


def test_item8_hashes_override(tmp_path: Path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dummy-override")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_fp, _ = emudhra_checks.cert_digests(cert)
    pem = tmp_path / "dummy.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Builtin list must not match.
    assert all(
        f.status != Status.FAIL
        for f in emudhra_checks.check_path(pem, hashes=compromised_hash_set())
    )
    # Override list flags it.
    findings = emudhra_checks.check_path(pem, hashes={cert_fp})
    assert any(f.status == Status.FAIL for f in findings)


# --- Items 9-10: LiteLLM ---


def test_item9_litellm_malicious_pin(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("litellm==1.107.0\n", encoding="utf-8")
    findings = litellm_checks.check_path(tmp_path, config=FIXED)
    fail = next(f for f in findings if f.status == Status.FAIL)
    assert "1.107.0" in fail.installed
    assert "Known-malicious release, rotate credentials immediately" in fail.remediation


@pytest.mark.parametrize("pin", ["1.106.9", "1.107.1"])
def test_item10_litellm_neighbors_pass(tmp_path: Path, pin: str):
    (tmp_path / "requirements.txt").write_text(f"litellm=={pin}\n", encoding="utf-8")
    findings = litellm_checks.check_path(tmp_path, config=FIXED)
    assert all(f.status == Status.PASS for f in findings)


# --- Item 11: certifi ---


def test_item11_certifi_floors():
    f17 = emudhra_checks.evaluate_certifi_version("2026.10.17", config=FIXED)
    f18 = emudhra_checks.evaluate_certifi_version("2026.10.18", config=FIXED)
    f19 = emudhra_checks.evaluate_certifi_version("2026.10.19", config=FIXED)
    assert f17.status == Status.FAIL
    assert f18.status == Status.PASS
    assert f19.status == Status.PASS
    assert "restores roots incorrectly dropped in 10.18" in f19.remediation


# --- Item 12: degrade to UNKNOWN ---


def test_item12_missing_php_unknown():
    findings = php_checks.check_local(php_bin="php-definitely-missing-xyz", config=FIXED)
    assert findings[0].status == Status.UNKNOWN
    assert findings[0].status != Status.PASS


# --- Item 14: CIDR / wildcard rejected ---


@pytest.mark.parametrize("target", ["192.168.1.0/24", "*", "*.example.com"])
def test_item14_rejects_ranges_and_wildcards(target: str):
    with pytest.raises(TargetError):
        assert_not_cidr_or_range(target)


# --- Item 16: JSON schema fields ---


def test_item16_json_schema_fields():
    fail = php_checks.evaluate_php_version("8.2.34", FIXED["php"]).to_dict()
    passed = php_checks.evaluate_php_version("8.2.35", FIXED["php"]).to_dict()
    for payload in (fail, passed):
        for key in (
            "cve_id",
            "installed_value",
            "fixed_value",
            "verdict",
            "detection_method",
            "remediation_step",
        ):
            assert key in payload
    assert fail["verdict"] == "FAIL"
    assert passed["verdict"] == "PASS"

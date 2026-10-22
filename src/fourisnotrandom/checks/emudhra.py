from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

from fourisnotrandom.config_loader import compromised_hash_set, load_fixed_versions
from fourisnotrandom.models import Finding, Status
from fourisnotrandom.targets import assert_not_cidr_or_range
from fourisnotrandom.versioning import (
    any_hash_match,
    certifi_exposure,
    go_exposure,
    normalize_hash,
)

CVE_LABEL = "CVE-2026-111943/CVE-2026-113470"
CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der"}
KEYSTORE_SUFFIXES = {".p12", ".pfx", ".pkcs12"}

CA_BUNDLE_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs",
]


def cert_digests(cert: x509.Certificate) -> tuple[str, str]:
    """Return (full_cert_sha256, spki_sha256) hex digests."""
    der = cert.public_bytes(Encoding.DER)
    cert_fp = hashlib.sha256(der).hexdigest()
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_fp = hashlib.sha256(spki).hexdigest()
    return cert_fp, spki_fp


def load_certs_from_pem_bytes(data: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    text = data.decode("utf-8", errors="ignore")
    if "BEGIN CERTIFICATE" in text:
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text,
            flags=re.S,
        )
        for block in blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(block.encode()))
            except ValueError:
                continue
    else:
        try:
            certs.append(x509.load_der_x509_certificate(data))
        except ValueError:
            pass
    return certs


def _match_finding(
    target: str,
    cert: x509.Certificate,
    hashes: set[str],
    *,
    detection_method: str = "certificate digest match",
) -> Finding | None:
    cert_fp, spki_fp = cert_digests(cert)
    hit = any_hash_match([cert_fp, spki_fp], hashes)
    subject = cert.subject.rfc4514_string()
    if hit:
        nh = normalize_hash(hit)
        if nh == normalize_hash(cert_fp):
            match_type = "full-certificate SHA-256"
        elif nh == normalize_hash(spki_fp):
            match_type = "SPKI SHA-256"
        else:
            match_type = "unknown"
        return Finding(
            status=Status.FAIL,
            cve=CVE_LABEL,
            target=target,
            installed=f"matched_via={match_type} matched={hit} subject={subject}",
            fixed="distrust / remove compromised intermediate",
            remediation="Remove or replace trust in compromised eMudhra intermediate; rotate any certs chaining through it.",
            detail="hash_match",
            detection_method=detection_method,
            extra={
                "cert_sha256": cert_fp,
                "spki_sha256": spki_fp,
                "matched": hit,
                "matched_via": match_type,
                "subject": subject,
            },
        )
    return None


def scan_certificates(
    certs: Iterable[x509.Certificate],
    target: str,
    hashes: set[str] | None = None,
) -> list[Finding]:
    hashes = hashes or compromised_hash_set()
    findings: list[Finding] = []
    matched = False
    certs_list = list(certs)
    for cert in certs_list:
        f = _match_finding(target, cert, hashes)
        if f:
            findings.append(f)
            matched = True
    if not matched:
        # Still surface digests for the first cert when present (auditability).
        extra: dict[str, Any] = {}
        if certs_list:
            c_fp, s_fp = cert_digests(certs_list[0])
            extra = {
                "cert_sha256": c_fp,
                "spki_sha256": s_fp,
                "matched": None,
                "matched_via": None,
            }
        findings.append(
            Finding(
                status=Status.PASS,
                cve=CVE_LABEL,
                target=target,
                installed="no compromised hash matched",
                fixed="N/A",
                remediation="No action required for eMudhra compromised intermediates on this target.",
                detail="no_match",
                detection_method="certificate digest match",
                extra=extra,
            )
        )
    return findings


def fetch_tls_chain(host: str, port: int = 443, timeout: float = 15.0) -> list[x509.Certificate]:
    assert_not_cidr_or_range(host)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            certs = [x509.load_der_x509_certificate(der)]
            # Peer cert only from stdlib; try getpeercert_chain if available (3.13+)
            chain = getattr(ssock, "getpeercert_chain", None)
            if callable(chain):
                for c in chain() or []:
                    try:
                        certs.append(x509.load_der_x509_certificate(c))
                    except Exception:
                        continue
            return certs


def check_host(host_or_url: str, hashes: set[str] | None = None) -> list[Finding]:
    assert_not_cidr_or_range(host_or_url)
    parsed = urlparse(host_or_url if "://" in host_or_url else f"https://{host_or_url}")
    host = parsed.hostname or host_or_url
    port = parsed.port or 443
    try:
        certs = fetch_tls_chain(host, port=port)
    except OSError as exc:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target=host,
                installed="?",
                fixed="",
                remediation=f"TLS connection failed: {exc}",
                detection_method="detected via TLS handshake",
            )
        ]
    findings = scan_certificates(certs, target=f"{host}:{port}", hashes=hashes)
    for f in findings:
        f.detection_method = "detected via TLS handshake"
    return findings


def check_path(path: str | Path, hashes: set[str] | None = None) -> list[Finding]:
    hashes = hashes or compromised_hash_set()
    root = Path(path)
    findings: list[Finding] = []
    files: list[Path] = []
    if root.is_file():
        files = [root]
    elif root.is_dir():
        for p in root.rglob("*"):
            if p.suffix.lower() in CERT_SUFFIXES | KEYSTORE_SUFFIXES and p.is_file():
                files.append(p)
    else:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target=str(root),
                installed="?",
                fixed="",
                remediation=f"Path not found: {root}",
            )
        ]

    if not files:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target=str(root),
                installed="?",
                fixed="",
                remediation="No certificate/keystore files found.",
            )
        ]

    any_fail = False
    scanned = 0
    for file in files:
        certs: list[x509.Certificate] = []
        suffix = file.suffix.lower()
        try:
            data = file.read_bytes()
        except OSError as exc:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve=CVE_LABEL,
                    target=str(file),
                    installed="?",
                    fixed="",
                    remediation=f"Unreadable: {exc}",
                )
            )
            continue
        if suffix in KEYSTORE_SUFFIXES:
            password = os.environ.get("CVE_EXPOSURE_KEYSTORE_PASSWORD")
            if password is None:
                findings.append(
                    Finding(
                        status=Status.UNKNOWN,
                        cve=CVE_LABEL,
                        target=str(file),
                        installed="pkcs12",
                        fixed="",
                        remediation="Set CVE_EXPOSURE_KEYSTORE_PASSWORD to scan this keystore (read-only).",
                    )
                )
                continue
            try:
                key, cert, addl = load_key_and_certificates(data, password.encode())
                del key
                if cert:
                    certs.append(cert)
                certs.extend(addl or [])
            except ValueError as exc:
                findings.append(
                    Finding(
                        status=Status.UNKNOWN,
                        cve=CVE_LABEL,
                        target=str(file),
                        installed="pkcs12",
                        fixed="",
                        remediation=f"Could not open keystore: {exc}",
                    )
                )
                continue
        else:
            certs = load_certs_from_pem_bytes(data)

        if not certs:
            continue
        scanned += 1
        for cert in certs:
            f = _match_finding(
                str(file),
                cert,
                hashes,
                detection_method="detected via PEM/keystore file",
            )
            if f:
                findings.append(f)
                any_fail = True

    if scanned and not any_fail and not any(f.status == Status.FAIL for f in findings):
        findings.append(
            Finding(
                status=Status.PASS,
                cve=CVE_LABEL,
                target=str(root),
                installed=f"scanned {scanned} file(s)",
                fixed="N/A",
                remediation="No compromised eMudhra hashes matched.",
                detection_method="detected via PEM/keystore file",
            )
        )
    elif not scanned and not findings:
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target=str(root),
                installed="?",
                fixed="",
                remediation="No parseable certificates found.",
            )
        )
    return findings


def _docker_extract_ca(image: str, dest: Path) -> list[Path]:
    """Extract common CA bundle paths from a local Docker image (explicit image name only)."""
    dest.mkdir(parents=True, exist_ok=True)
    cid_proc = subprocess.run(
        ["docker", "create", image],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if cid_proc.returncode != 0:
        raise RuntimeError(cid_proc.stderr.strip() or "docker create failed")
    cid = cid_proc.stdout.strip()
    extracted: list[Path] = []
    try:
        for remote in CA_BUNDLE_PATHS:
            local = dest / remote.lstrip("/").replace("/", "_")
            cp = subprocess.run(
                ["docker", "cp", f"{cid}:{remote}", str(local)],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            if cp.returncode == 0 and local.exists():
                extracted.append(local)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False, timeout=60)
    return extracted


def check_docker(image_or_dockerfile: str, hashes: set[str] | None = None) -> list[Finding]:
    hashes = hashes or compromised_hash_set()
    path = Path(image_or_dockerfile)
    if path.is_file() and path.name.lower().startswith("dockerfile"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        findings: list[Finding] = []
        # Look for COPY/ADD of cert bundles referenced relatively
        for m in re.finditer(r"^\s*(?:COPY|ADD)\s+(\S+)\s+(\S+)", text, re.M | re.I):
            src = path.parent / m.group(1)
            if src.exists():
                findings.extend(check_path(src, hashes=hashes))
        if not findings:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve=CVE_LABEL,
                    target=str(path),
                    installed="Dockerfile",
                    fixed="",
                    remediation="No local CA bundle paths found via COPY/ADD; scan the built image with --docker IMAGE.",
                )
            )
        return findings

    # Treat as image name
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="cve-emudhra-") as tmp:
            extracted = _docker_extract_ca(image_or_dockerfile, Path(tmp))
            if not extracted:
                return [
                    Finding(
                        status=Status.UNKNOWN,
                        cve=CVE_LABEL,
                        target=image_or_dockerfile,
                        installed="?",
                        fixed="",
                        remediation="Could not extract CA bundles from image (is Docker available and image local?).",
                    )
                ]
            out: list[Finding] = []
            for p in extracted:
                out.extend(check_path(p, hashes=hashes))
            return out
    except (RuntimeError, FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target=image_or_dockerfile,
                installed="?",
                fixed="",
                remediation=f"Docker scan failed: {exc}",
            )
        ]


def check_toolchains(config: dict[str, Any] | None = None) -> list[Finding]:
    data = config or load_fixed_versions()
    findings: list[Finding] = []

    # Go
    go_cfg = data.get("go", {})
    try:
        proc = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=15, check=False)
        banner = (proc.stdout or "") + (proc.stderr or "")
        # Official toolchain: "go version go1.27.3 windows/amd64"
        m = re.search(r"go version go(?P<v>\d+\.\d+(?:\.\d+)?)", banner, re.I)
        ver = m.group("v") if m else ""
        if ver:
            status_s, fixed, reason = go_exposure(ver, go_cfg.get("fixed_by_branch", {}))
            findings.append(
                Finding(
                    status=Status[status_s],
                    cve="/".join(go_cfg.get("cves", [CVE_LABEL])),
                    target="go",
                    installed=ver,
                    fixed=fixed,
                    remediation=go_cfg.get("remediation", "Upgrade Go.") if status_s == "FAIL" else (
                        "No action required." if status_s == "PASS" else "Verify Go version."
                    ),
                    detail=reason,
                )
            )
        else:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve="/".join(go_cfg.get("cves", [CVE_LABEL])),
                    target="go",
                    installed="not golang toolchain",
                    fixed="",
                    remediation="Go toolchain not detected (expected `go version goX.Y.Z ...` on PATH).",
                )
            )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve="/".join(go_cfg.get("cves", [CVE_LABEL])),
                target="go",
                installed="not installed",
                fixed="",
                remediation="Go toolchain not found on PATH.",
            )
        )

    # certifi
    cert_cfg = data.get("certifi", {})
    min_safe = cert_cfg.get("min_safe", "2026.10.18")
    ver = ""
    try:
        import certifi as certifi_mod  # type: ignore

        ver = getattr(certifi_mod, "__version__", "") or ""
    except Exception:
        try:
            proc = subprocess.run(
                ["pip", "show", "certifi"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            m = re.search(r"^Version:\s*(\S+)", proc.stdout or "", re.M)
            ver = m.group(1) if m else ""
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            ver = ""

    if not ver:
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve=CVE_LABEL,
                target="certifi",
                installed="not installed",
                fixed=min_safe,
                remediation="certifi not found; install/upgrade to 2026.10.18+ if used.",
            )
        )
    else:
        findings.append(
            evaluate_certifi_version(ver, config=data, detection_method="detected via installed certifi package")
        )
    return findings


def evaluate_certifi_version(
    version: str,
    config: dict[str, Any] | None = None,
    *,
    detection_method: str = "detected via supplied version string",
) -> Finding:
    data = config or load_fixed_versions()
    cert_cfg = data.get("certifi", {})
    min_safe = cert_cfg.get("min_safe", "2026.10.18")
    status_s, fixed, reason = certifi_exposure(version, min_safe)
    note = cert_cfg.get("note", "")
    if status_s == "FAIL":
        rem = cert_cfg.get("remediation", "Upgrade certifi.")
    elif status_s == "PASS":
        # Prefer explicit note when the installed build is the stability follow-up.
        if version.strip() == "2026.10.19" or version.strip().startswith("2026.10.19"):
            rem = cert_cfg.get(
                "remediation_restored",
                "PASS - also restores roots incorrectly dropped in 10.18.",
            )
        else:
            rem = "No action required." + (f" ({note})" if note else "")
    else:
        rem = "Verify certifi version."
    return Finding(
        status=Status[status_s],
        cve=CVE_LABEL,
        target="certifi",
        installed=version,
        fixed=fixed,
        remediation=rem,
        detail=reason + (f"; note={note}" if note else ""),
        detection_method=detection_method,
    )

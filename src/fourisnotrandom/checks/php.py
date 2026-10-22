from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml

from fourisnotrandom.checks.apps import detect_php_apps
from fourisnotrandom.config_loader import load_fixed_versions
from fourisnotrandom.models import Finding, Status
from fourisnotrandom.targets import assert_not_cidr_or_range
from fourisnotrandom.versioning import (
    extract_php_version_from_banner,
    parse_version,
    php_exposure,
)

SAPI_LABELS = {
    "apache2handler": "mod_php",
    "cgi": "php-cgi",
    "cgi-fcgi": "php-cgi",
    "litespeed": "LiteSpeed",
    "frankenphp": "FrankenPHP",
}


def _php_cfg(config: dict[str, Any] | None = None) -> dict[str, Any]:
    data = config or load_fixed_versions()
    return data["php"]


def _status_from_code(code: str) -> Status:
    return Status[code] if code in Status.__members__ else Status.UNKNOWN


def _cve_label(php_cfg: dict[str, Any]) -> str:
    return "/".join(php_cfg.get("cves", ["CVE-2026-109618", "CVE-2026-109619"]))


def evaluate_php_version(
    version: str | None,
    php_cfg: dict[str, Any] | None = None,
    *,
    detection_method: str = "detected via supplied version string",
    target: str = "php",
) -> Finding:
    cfg = php_cfg or _php_cfg()
    if version is None:
        return Finding(
            status=Status.UNKNOWN,
            cve=_cve_label(cfg),
            target=target,
            installed="None",
            fixed="",
            remediation="Unable to determine exposure; version value was None.",
            detail="unparseable",
            detection_method=detection_method,
        )
    status_s, fixed, reason = php_exposure(
        version,
        cfg.get("fixed_by_branch", {}),
        cfg.get("unsupported_major_at_or_below", "8.1"),
    )
    if reason == "eol_no_fix":
        rem = cfg.get(
            "remediation_eol",
            "No fix available, major upgrade required.",
        )
    else:
        rem = cfg.get("remediation_fixed", "Upgrade PHP to the fixed version.")
    if status_s == "FAIL":
        remediation = rem
    elif status_s == "PASS":
        remediation = "No action required."
    else:
        remediation = (
            f"Unable to determine exposure ({reason}); verify PHP version manually."
        )
    return Finding(
        status=_status_from_code(status_s),
        cve=_cve_label(cfg),
        target=target,
        installed=str(version),
        fixed=fixed or "see fixed_versions.yaml",
        remediation=remediation,
        detail=reason,
        detection_method=detection_method,
    )


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return out


def check_local(php_bin: str = "php", config: dict[str, Any] | None = None) -> list[Finding]:
    cfg = _php_cfg(config)
    findings: list[Finding] = []
    try:
        banner = _run([php_bin, "-v"])
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=_cve_label(cfg),
                target=php_bin,
                installed="?",
                fixed="",
                remediation=f"Could not run {php_bin!r}: {exc}",
                detail="php_missing",
                detection_method="detected via php -v",
            )
        ]

    version = extract_php_version_from_banner(banner) or ""
    if not version:
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve=_cve_label(cfg),
                target=php_bin,
                installed=banner.strip().splitlines()[0] if banner.strip() else "?",
                fixed="",
                remediation="Could not parse PHP version from php -v.",
                detection_method="detected via php -v",
            )
        )
        return findings

    finding = evaluate_php_version(
        version, cfg, detection_method="detected via php -v", target=php_bin
    )
    findings.append(finding)

    # SAPI + session.upload_progress (read-only)
    try:
        info = _run([php_bin, "-i"])
    except (OSError, subprocess.TimeoutExpired):
        info = ""

    sapi_m = re.search(r"^Server API\s*=>\s*(.+)$", info, re.M)
    sapi = (sapi_m.group(1).strip().lower() if sapi_m else "")
    for key, label in SAPI_LABELS.items():
        if key in sapi or label.lower() in sapi:
            if finding.status == Status.FAIL:
                findings.append(
                    Finding(
                        status=Status.FAIL,
                        cve=_cve_label(cfg),
                        target=php_bin,
                        installed=f"{version} SAPI={label}",
                        fixed=finding.fixed,
                        remediation=f"High-risk SAPI {label} on vulnerable PHP - upgrade PHP immediately.",
                        detail="high_risk_sapi",
                    )
                )
            break

    up_m = re.search(
        r"session\.upload_progress\.enabled\s*=>\s*(\w+)\s*=>\s*(\w+)",
        info,
        re.I,
    )
    if up_m:
        enabled = up_m.group(2).lower() in {"on", "1", "true"}
        findings.append(
            Finding(
                status=Status.FAIL if (enabled and finding.status == Status.FAIL) else (
                    Status.PASS if not enabled else Status.UNKNOWN
                ),
                cve=_cve_label(cfg),
                target=php_bin,
                installed=f"session.upload_progress.enabled={'On' if enabled else 'Off'}",
                fixed="Off (compensating control only; not a complete fix)",
                remediation=(
                    "session.upload_progress.enabled is On on vulnerable PHP - upgrade PHP; do not rely on toggling this alone."
                    if enabled and finding.status == Status.FAIL
                    else (
                        "upload_progress disabled (compensating only)."
                        if not enabled
                        else "Noted upload_progress setting; ensure PHP is patched."
                    )
                ),
                detail="upload_progress_readonly",
            )
        )
    return findings


def check_remote(
    url: str,
    fingerprint_url: str | None = None,
    config: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> list[Finding]:
    """Fingerprint PHP from HTTP headers / optional user-supplied safe URL. No exploit payloads."""
    cfg = _php_cfg(config)
    assert_not_cidr_or_range(url)
    findings: list[Finding] = []
    targets = [url]
    if fingerprint_url:
        assert_not_cidr_or_range(fingerprint_url)
        if fingerprint_url.startswith("http"):
            targets.append(fingerprint_url)
        else:
            targets.append(urljoin(url if url.endswith("/") else url + "/", fingerprint_url.lstrip("/")))

    headers_blob = ""
    last_err = ""
    for t in targets:
        try:
            resp = requests.get(
                t,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "FourIsNotRandom/0.1 (detection-only)"},
            )
            for k, v in resp.headers.items():
                headers_blob += f"{k}: {v}\n"
            headers_blob += resp.text[:2048]
        except requests.RequestException as exc:
            last_err = str(exc)

    version = extract_php_version_from_banner(headers_blob)
    if not version:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=_cve_label(cfg),
                target=url,
                installed="?",
                fixed="",
                remediation=last_err
                or "No PHP version in headers/banner; supply --fingerprint-url if you have a safe banner endpoint.",
                detail="no_remote_version",
                detection_method="detected via HTTP headers",
            )
        ]
    finding = evaluate_php_version(
        version, cfg, detection_method="detected via HTTP headers", target=url
    )
    findings.append(finding)
    return findings


_FROM_PHP_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<img>\S*php\S*)(?::(?P<tag>\S+))?",
    re.I | re.M,
)
_PHP_TAG_RE = re.compile(r"(?P<v>\d+\.\d+(?:\.\d+)?)")
_COMPOSER_PHP_RE = re.compile(r'"php"\s*:\s*"[^"]*?(\d+\.\d+(?:\.\d+)?)')
_DPKG_PHP_RE = re.compile(
    r"^Package:\s*php(?:\d+(?:\.\d+)?)?(?:-cli|-fpm)?\s*$[\s\S]*?^Version:\s*(?P<v>[\d.]+)",
    re.M | re.I,
)


def _versions_from_dockerfile(text: str) -> list[str]:
    versions: list[str] = []
    for m in _FROM_PHP_RE.finditer(text):
        tag = m.group("tag") or ""
        img = m.group("img") or ""
        blob = f"{img}:{tag}"
        vm = _PHP_TAG_RE.search(tag) or _PHP_TAG_RE.search(img)
        if vm:
            versions.append(vm.group("v"))
        elif "php" in blob.lower():
            # unpinned
            versions.append("unpinned")
    return versions


def _versions_from_compose(text: str) -> list[str]:
    versions: list[str] = []
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return versions
    services = data.get("services") or {}
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        image = str(svc.get("image") or "")
        if "php" in image.lower():
            vm = _PHP_TAG_RE.search(image)
            versions.append(vm.group("v") if vm else "unpinned")
    return versions


def check_filesystem(path: str | Path, config: dict[str, Any] | None = None) -> list[Finding]:
    cfg = _php_cfg(config)
    root = Path(path)
    findings: list[Finding] = []
    versions: list[tuple[str, str, str]] = []  # (version, source, detection_method)

    if not root.exists():
        return [
            Finding(
                status=Status.UNKNOWN,
                cve=_cve_label(cfg),
                target=str(root),
                installed="?",
                fixed="",
                remediation=f"Path not found: {root}",
            )
        ]

    candidates: list[Path] = []
    if root.is_file():
        candidates = [root]
    else:
        seen: set[Path] = set()
        for name in (
            "Dockerfile",
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "composer.lock",
            "composer.json",
        ):
            p = root / name
            if not p.is_file():
                continue
            # Windows case-insensitive FS: Dockerfile and dockerfile resolve to one file.
            resolved = p.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            candidates.append(p)
        # dpkg status snippets
        for p in root.rglob("status"):
            if p.is_file() and "dpkg" in str(p).lower():
                candidates.append(p)
                break

    for file in candidates:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        name = file.name.lower()
        if name.startswith("dockerfile"):
            for v in _versions_from_dockerfile(text):
                versions.append((v, str(file), "detected via Dockerfile FROM line"))
        elif name == "composer.lock":
            # Must precede the "compose" substring check (composer.lock contains "compose").
            try:
                lock = json.loads(text)
                platform = (lock.get("platform") or {}).get("php")
                if platform:
                    parsed = parse_version(platform)
                    versions.append(
                        (
                            parsed.raw if parsed else platform,
                            str(file),
                            "detected via composer.lock",
                        )
                    )
            except json.JSONDecodeError:
                m = _COMPOSER_PHP_RE.search(text)
                if m:
                    versions.append((m.group(1), str(file), "detected via composer.lock"))
        elif name == "composer.json":
            m = _COMPOSER_PHP_RE.search(text)
            if m:
                versions.append((m.group(1), str(file), "detected via composer.json"))
        elif name in {
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        } or (
            "compose" in name and name.endswith((".yml", ".yaml"))
        ):
            for v in _versions_from_compose(text):
                versions.append((v, str(file), "detected via docker-compose image"))
        elif name == "status":
            for m in _DPKG_PHP_RE.finditer(text):
                versions.append((m.group("v"), str(file), "detected via dpkg status"))

    php_status: str | None = None
    php_version: str | None = None
    if not versions:
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve=_cve_label(cfg),
                target=str(root),
                installed="?",
                fixed="",
                remediation="No pinned PHP version found in Docker/compose/composer/dpkg artifacts.",
                detail="no_fs_version",
                detection_method="filesystem scan",
            )
        )
    else:
        for ver, source, method in versions:
            if ver == "unpinned":
                findings.append(
                    Finding(
                        status=Status.UNKNOWN,
                        cve=_cve_label(cfg),
                        target=source,
                        installed="unpinned",
                        fixed="pin to a fixed PHP tag",
                        remediation="PHP image/tag is unpinned; pin to a fixed version (e.g. 8.3.36).",
                        detection_method=method,
                    )
                )
                continue
            f = evaluate_php_version(ver, cfg, detection_method=method, target=source)
            findings.append(f)
            php_version = ver
            php_status = f.status.value

    # Application stack fingerprints when scanning a directory
    if root.is_dir():
        findings.extend(
            detect_php_apps(root, php_version=php_version, php_status=php_status)
        )
    return findings

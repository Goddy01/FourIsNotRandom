from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from fourisnotrandom.config_loader import load_fixed_versions
from fourisnotrandom.models import Finding, Status
from fourisnotrandom.targets import assert_not_cidr_or_range
from fourisnotrandom.versioning import gitlab_exposure, parse_version


def _base_url(url: str) -> str:
    assert_not_cidr_or_range(url)
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if not parsed.scheme:
        parsed = urlparse(f"https://{url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def discover_version(base: str, timeout: float = 15.0) -> tuple[str | None, str, str]:
    """Read-only version discovery via GitLab public endpoints.

    Returns (version, source_url, detection_method).
    """
    headers = {"User-Agent": "FourIsNotRandom/0.1 (detection-only)"}
    # Prefer version API - preserve full string (e.g. 19.3.5-internal0).
    api = urljoin(base + "/", "api/v4/version")
    try:
        resp = requests.get(api, timeout=timeout, headers=headers)
        if resp.ok:
            data = resp.json()
            if isinstance(data, dict) and data.get("version"):
                return (
                    str(data["version"]),
                    api,
                    "detected via /api/v4/version",
                )
    except (requests.RequestException, ValueError):
        pass

    help_url = urljoin(base + "/", "help")
    try:
        resp = requests.get(help_url, timeout=timeout, headers=headers)
        text = resp.text or ""
        # Common patterns on /help - allow Dedicated internal suffixes.
        patterns = [
            r"GitLab\s+(?:Community|Enterprise)\s+Edition\s+[vV]?(?P<v>\d+\.\d+\.\d+(?:[-._][A-Za-z0-9.+]+)?)",
            r"data-version=\"(?P<v>\d+\.\d+\.\d+(?:[-._][A-Za-z0-9.+]+)?)\"",
            r"GitLab\s+[vV]?(?P<v>\d+\.\d+(?:\.\d+)?(?:[-._][A-Za-z0-9.+]+)?)",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group("v"), help_url, "detected via /help"
    except requests.RequestException:
        pass
    return None, help_url, "detected via /help"


def _remediation_for(status_s: str, reason: str, meta: dict[str, Any]) -> str:
    if status_s == "PASS":
        if reason == "newer_than_table":
            return meta.get(
                "remediation_beyond_table",
                "Beyond the known fixed-version table; manually confirm against GitLab's current advisory.",
            )
        if reason == "not_in_affected_range":
            return "No action required for this CVE (outside the affected version range)."
        if reason == "dedicated_internal_build":
            return "GitLab Dedicated internal build - treated as already patched per GitLab advisory notes."
        return "No action required for this CVE."
    if status_s == "UNKNOWN":
        return "Unable to map GitLab version to advisory floors; verify manually."
    if reason == "no_backport":
        return meta.get(
            "remediation_no_backport",
            "No backport available for this branch, full upgrade required.",
        )
    return meta.get("remediation", "Upgrade GitLab.")


def evaluate_gitlab_version(
    version: str,
    config: dict[str, Any] | None = None,
    *,
    detection_method: str = "detected via supplied version string",
    target: str = "gitlab",
) -> list[Finding]:
    """Offline evaluation of an installed GitLab version string against both CVEs."""
    data = config or load_fixed_versions()
    gl = data.get("gitlab", {})
    cves = gl.get("cves", {})
    findings: list[Finding] = []
    parsed = parse_version(version)
    installed = parsed.raw if parsed else version

    for cve_id, meta in cves.items():
        status_s, fixed, reason = gitlab_exposure(
            installed,
            meta.get("fixed_by_branch", {}),
            meta.get("min_affected"),
            meta.get("max_affected"),
        )
        findings.append(
            Finding(
                status=Status[status_s],
                cve=cve_id,
                target=target,
                installed=installed,
                fixed=fixed or "see fixed_versions.yaml",
                remediation=_remediation_for(status_s, reason, meta),
                detail=reason,
                detection_method=detection_method,
                extra={"description": meta.get("description", "")},
            )
        )
    return findings


def check_gitlab(url: str, config: dict[str, Any] | None = None, timeout: float = 15.0) -> list[Finding]:
    data = config or load_fixed_versions()
    gl = data.get("gitlab", {})
    cves = gl.get("cves", {})
    base = _base_url(url)
    version, source, method = discover_version(base, timeout=timeout)

    if not version:
        findings: list[Finding] = []
        for cve_id in cves or ["CVE-2026-110264", "CVE-2026-97229"]:
            findings.append(
                Finding(
                    status=Status.UNKNOWN,
                    cve=str(cve_id),
                    target=base,
                    installed="?",
                    fixed="",
                    remediation="Could not read GitLab version from /api/v4/version or /help.",
                    detail="version_undisclosed",
                    detection_method=method,
                )
            )
        return findings

    return evaluate_gitlab_version(
        version,
        config=data,
        detection_method=method,
        target=source or base,
    )

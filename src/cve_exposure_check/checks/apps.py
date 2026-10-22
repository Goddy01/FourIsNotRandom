from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cve_exposure_check.config_loader import load_php_apps
from cve_exposure_check.models import Finding, Status


def detect_php_apps(
    root: Path,
    php_version: str | None = None,
    php_status: str | None = None,
    apps_config: dict[str, Any] | None = None,
) -> list[Finding]:
    """Detect common PHP application stacks under a webroot (read-only)."""
    cfg = apps_config or load_php_apps()
    findings: list[Finding] = []
    root = Path(root)

    for app in cfg.get("apps", []):
        name = app.get("name", "unknown")
        matched = False
        version_hint = ""
        for marker in app.get("markers", []):
            rel = marker.get("path")
            if not rel:
                continue
            path = root / rel
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            contains = marker.get("contains")
            if contains and contains not in text:
                continue
            pattern = marker.get("pattern")
            if pattern:
                m = re.search(pattern, text)
                if not m:
                    continue
                version_hint = m.group(1).strip() if m.lastindex else ""
            matched = True
            break

        if not matched:
            continue

        if php_status == "FAIL":
            status = Status.FAIL
            remediation = (
                f"{name} detected on vulnerable PHP {php_version or '?'}; "
                "upgrade PHP (and review app compatibility)."
            )
        elif php_version:
            status = Status.PASS if php_status == "PASS" else Status.UNKNOWN
            remediation = (
                f"{name} detected; confirm PHP {php_version} is on a fixed branch."
                if status != Status.PASS
                else f"{name} detected; PHP version appears fixed."
            )
        else:
            status = Status.UNKNOWN
            remediation = f"{name} detected; PHP version not determined — run a PHP check."

        findings.append(
            Finding(
                status=status,
                cve="CVE-2026-109618/CVE-2026-109619",
                target=str(root),
                installed=f"{name}" + (f" {version_hint}" if version_hint else ""),
                fixed="PHP fixed branch (see php check)",
                remediation=remediation,
                detail="application_stack",
                extra={"app": name, "app_version": version_hint, "php_version": php_version},
            )
        )
    return findings

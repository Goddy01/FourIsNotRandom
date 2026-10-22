from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from cve_exposure_check.config_loader import load_fixed_versions
from cve_exposure_check.models import Finding, Status
from cve_exposure_check.versioning import litellm_is_compromised

REQ_RE = re.compile(
    r"^\s*litellm\s*(?:==|===|@)\s*[\"']?(?P<v>[\d.]+(?:[a-zA-Z0-9._-]*)?)[\"']?",
    re.I | re.M,
)
LOCK_RE = re.compile(
    r'name\s*=\s*"litellm"[\s\S]{0,200}?version\s*=\s*"(?P<v>[^"]+)"',
    re.I,
)
PIP_RE = re.compile(r"^litellm\s+(?P<v>\S+)", re.I | re.M)


def _cfg(config: dict[str, Any] | None = None) -> dict[str, Any]:
    data = config or load_fixed_versions()
    return data.get("litellm", {})


def _finding(
    target: str,
    version: str,
    cfg: dict[str, Any],
    *,
    detection_method: str = "detected via dependency pin",
) -> Finding:
    compromised = cfg.get("compromised_version", "1.107.0")
    if litellm_is_compromised(version, compromised):
        return Finding(
            status=Status.FAIL,
            cve="LiteLLM-1.107.0-supply-chain",
            target=target,
            installed=f"litellm=={version}",
            fixed=f"not {compromised} (e.g. {cfg.get('safe_pin_example', '1.106.2')})",
            remediation=cfg.get(
                "remediation",
                "Known-malicious release, rotate credentials immediately.",
            ),
            detail="exact_compromised_pin",
            detection_method=detection_method,
        )
    return Finding(
        status=Status.PASS,
        cve="LiteLLM-1.107.0-supply-chain",
        target=target,
        installed=f"litellm=={version}",
        fixed=f"not {compromised}",
        remediation="No action required for the 1.107.0 compromise pin.",
        detail="not_compromised_pin",
        detection_method=detection_method,
    )


def check_env(config: dict[str, Any] | None = None) -> list[Finding]:
    cfg = _cfg(config)
    try:
        proc = subprocess.run(
            ["pip", "list", "--format=freeze"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        text = proc.stdout or ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve="LiteLLM-1.107.0-supply-chain",
                target="pip",
                installed="?",
                fixed="",
                remediation=f"Could not run pip list: {exc}",
            )
        ]

    findings: list[Finding] = []
    for m in re.finditer(r"^litellm==(?P<v>\S+)", text, re.I | re.M):
        findings.append(
            _finding("pip", m.group("v"), cfg, detection_method="detected via pip list")
        )
    if not findings:
        # Also try pip list human format
        try:
            proc2 = subprocess.run(
                ["pip", "list"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            for m in PIP_RE.finditer(proc2.stdout or ""):
                findings.append(
                    _finding(
                        "pip", m.group("v"), cfg, detection_method="detected via pip list"
                    )
                )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass
    if not findings:
        findings.append(
            Finding(
                status=Status.PASS,
                cve="LiteLLM-1.107.0-supply-chain",
                target="pip",
                installed="litellm not installed",
                fixed="not 1.107.0",
                remediation="No litellm package in this environment.",
                detection_method="detected via pip list",
            )
        )
    return findings


def _scan_text(text: str, source: str, cfg: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    method = f"detected via {Path(source).name}"
    for m in REQ_RE.finditer(text):
        findings.append(_finding(source, m.group("v"), cfg, detection_method=method))
    for m in LOCK_RE.finditer(text):
        findings.append(_finding(source, m.group("v"), cfg, detection_method=method))
    # poetry.lock / uv style "litellm" blocks already covered; also package.json-like
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            # pip freeze json / poetry
            pkgs = data.get("packages") or data.get("default") or {}
            if isinstance(pkgs, list):
                for pkg in pkgs:
                    if isinstance(pkg, dict) and str(pkg.get("name", "")).lower() == "litellm":
                        ver = str(pkg.get("version", ""))
                        if ver:
                            findings.append(
                                _finding(source, ver, cfg, detection_method=method)
                            )
            elif isinstance(pkgs, dict) and "litellm" in {k.lower() for k in pkgs}:
                for k, v in pkgs.items():
                    if k.lower() == "litellm":
                        ver = v if isinstance(v, str) else str(v.get("version", v))
                        ver = ver.lstrip("=")
                        findings.append(
                            _finding(source, ver, cfg, detection_method=method)
                        )
    except json.JSONDecodeError:
        pass
    return findings


def check_path(path: str | Path, config: dict[str, Any] | None = None) -> list[Finding]:
    cfg = _cfg(config)
    root = Path(path)
    findings: list[Finding] = []
    names = (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.lock",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
    )
    files: list[Path] = []
    if root.is_file():
        files = [root]
    elif root.is_dir():
        for name in names:
            p = root / name
            if p.is_file():
                files.append(p)
        for p in root.glob("requirements*.txt"):
            if p not in files:
                files.append(p)
    else:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve="LiteLLM-1.107.0-supply-chain",
                target=str(root),
                installed="?",
                fixed="",
                remediation=f"Path not found: {root}",
            )
        ]

    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_scan_text(text, str(file), cfg))

    if not findings:
        findings.append(
            Finding(
                status=Status.PASS,
                cve="LiteLLM-1.107.0-supply-chain",
                target=str(root),
                installed="litellm pin not found",
                fixed="not 1.107.0",
                remediation="No litellm==1.107.0 pin found in scanned dependency files.",
            )
        )
    return findings


def check_docker(image: str, config: dict[str, Any] | None = None) -> list[Finding]:
    """Detection-only: inspect image tags/labels and optionally pip freeze inside create+cp."""
    cfg = _cfg(config)
    compromised = cfg.get("compromised_version", "1.107.0")
    findings: list[Finding] = []

    # Tag heuristic
    if compromised in image:
        findings.append(_finding(image, compromised, cfg))
        return findings

    try:
        inspect = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        blob = inspect.stdout or ""
        if compromised in blob:
            findings.append(_finding(image, compromised, cfg))
            return findings
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return [
            Finding(
                status=Status.UNKNOWN,
                cve="LiteLLM-1.107.0-supply-chain",
                target=image,
                installed="?",
                fixed="",
                remediation=f"Docker inspect failed: {exc}",
            )
        ]

    # Try extracting a freeze file if present (best-effort, local image)
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="cve-litellm-") as tmp:
            cid_proc = subprocess.run(
                ["docker", "create", image],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if cid_proc.returncode != 0:
                return [
                    Finding(
                        status=Status.UNKNOWN,
                        cve="LiteLLM-1.107.0-supply-chain",
                        target=image,
                        installed="?",
                        fixed="",
                        remediation="Could not create container from image to inspect packages.",
                    )
                ]
            cid = cid_proc.stdout.strip()
            try:
                dest = Path(tmp) / "METADATA"
                # Common site-packages METADATA path patterns are deep; try pip freeze via docker run --entrypoint
                freeze = subprocess.run(
                    ["docker", "run", "--rm", "--entrypoint", "pip", image, "freeze"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                text = freeze.stdout or ""
                hits = list(re.finditer(r"^litellm==(?P<v>\S+)", text, re.I | re.M))
                if hits:
                    for m in hits:
                        findings.append(_finding(image, m.group("v"), cfg))
                else:
                    findings.append(
                        Finding(
                            status=Status.PASS,
                            cve="LiteLLM-1.107.0-supply-chain",
                            target=image,
                            installed="litellm not found in pip freeze",
                            fixed=f"not {compromised}",
                            remediation="No litellm==1.107.0 detected in image pip freeze.",
                        )
                    )
            finally:
                subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False, timeout=60)
                # dest unused if freeze worked
                _ = dest
    except (OSError, subprocess.TimeoutExpired) as exc:
        findings.append(
            Finding(
                status=Status.UNKNOWN,
                cve="LiteLLM-1.107.0-supply-chain",
                target=image,
                installed="?",
                fixed="",
                remediation=f"Docker package scan failed: {exc}",
            )
        )
    return findings

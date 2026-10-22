"""Explicit-target validation - reject CIDR / range sweeps."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


_CIDR_RE = re.compile(r"/\d{1,3}\s*$")
_RANGE_RE = re.compile(r"\d+\.\d+\.\d+\.\d+\s*-\s*\d+")


class TargetError(ValueError):
    pass


def assert_not_cidr_or_range(value: str) -> str:
    text = value.strip()
    if not text:
        raise TargetError("Empty target")
    # Reject bare wildcards / glob-style sweeps (never expand into a scan).
    if text in {"*", "?", "*.*", "*.*.*.*"} or (
        "*" in text and "://" not in text and "/" not in text.replace("\\", "/")
    ):
        raise TargetError(
            f"Refusing wildcard target {text!r}. "
            "Pass an explicit hostname, IP, URL, or path - wildcards are not expanded."
        )
    if _CIDR_RE.search(text) or _RANGE_RE.search(text):
        raise TargetError(
            f"Refusing network range/CIDR target {text!r}. "
            "Pass an explicit hostname, IP, URL, or path."
        )
    # Reject pure network objects
    candidate = text
    if "://" in text:
        host = urlparse(text).hostname or ""
        candidate = host
    if candidate:
        try:
            net = ipaddress.ip_network(candidate, strict=False)
            if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and net.num_addresses > 1:
                raise TargetError(
                    f"Refusing network range {text!r}. Pass a single host only."
                )
        except ValueError:
            pass
        # Single IP is OK; bare CIDR string already caught above
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
    return text


def load_targets_file(path: Path) -> list[str]:
    lines: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(assert_not_cidr_or_range(line))
    if not lines:
        raise TargetError(f"No targets found in {path}")
    return lines

"""Version comparison helpers for PHP, GitLab, Go, and certifi date versions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from packaging.version import InvalidVersion, Version


_VERSION_RE = re.compile(
    r"(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?(?:[-._]?(?P<suffix>[a-zA-Z0-9.+-]+))?"
)


@dataclass(frozen=True)
class ParsedVersion:
    major: int
    minor: int
    patch: int
    raw: str
    suffix: str = ""

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def parse_version(text: str) -> ParsedVersion | None:
    """Extract a dotted version from free-form banner text."""
    if not text:
        return None
    cleaned = text.strip()
    # Prefer first X.Y.Z-like token.
    match = _VERSION_RE.search(cleaned)
    if not match:
        return None
    patch = match.group("patch")
    return ParsedVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(patch) if patch is not None else 0,
        suffix=(match.group("suffix") or "").lower(),
        raw=match.group(0),
    )


def _cmp_tuple(a: ParsedVersion, b: ParsedVersion) -> int:
    ta, tb = a.as_tuple(), b.as_tuple()
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def is_at_least(installed: ParsedVersion, floor: ParsedVersion) -> bool:
    return _cmp_tuple(installed, floor) >= 0


def php_exposure(
    installed_text: str,
    fixed_by_branch: dict[str, str],
    unsupported_major_at_or_below: str = "8.1",
) -> tuple[str, str, str]:
    """
    Return (status, fixed_hint, reason_code).

    status: PASS | FAIL | UNKNOWN
    """
    installed = parse_version(installed_text)
    if not installed:
        return "UNKNOWN", "", "unparseable"

    eol = parse_version(unsupported_major_at_or_below)
    if eol and _cmp_tuple(installed, ParsedVersion(eol.major, eol.minor, 999, eol.raw)) <= 0:
        # major.minor <= 8.1 → must upgrade major
        if (installed.major, installed.minor) <= (eol.major, eol.minor):
            return "FAIL", f">{eol.branch}+ fixed branch", "eol_no_fix"

    floor_text = fixed_by_branch.get(installed.branch)
    if not floor_text:
        # Newer unsupported-in-table branch: treat as UNKNOWN if above known max,
        # FAIL if below all known branches somehow.
        known = sorted(
            (parse_version(v) for v in fixed_by_branch.values()),
            key=lambda p: p.as_tuple() if p else (0, 0, 0),
        )
        known = [k for k in known if k]
        if known and installed.as_tuple() > known[-1].as_tuple():
            return "PASS", known[-1].raw, "newer_than_table"
        return "UNKNOWN", "", "unknown_branch"

    floor = parse_version(floor_text)
    if not floor:
        return "UNKNOWN", floor_text, "bad_floor_config"

    if is_at_least(installed, floor):
        return "PASS", floor.raw, "at_or_above_fixed"
    return "FAIL", floor.raw, "below_fixed"


def gitlab_exposure(
    installed_text: str,
    fixed_by_branch: dict[str, str],
    min_affected: str | None = None,
    max_affected: str | None = None,
) -> tuple[str, str, str]:
    """
    Branch-relative GitLab comparison.

    If installed branch is newer than all listed floors and not otherwise
    covered, PASS. If below min_affected, PASS (not in affected range).
    If above max_affected (closed advisory window), PASS with
    ``not_in_affected_range`` — confirmed N/A, not "unknown / beyond table".
    Without max_affected, versions above the newest listed floor use
    ``newer_than_table`` (PASS, but manually confirm).
    GitLab Dedicated internal builds (suffix contains ``internal``) are treated
    as already patched per GitLab's advisory notes.
    """
    installed = parse_version(installed_text)
    if not installed:
        return "UNKNOWN", "", "unparseable"

    # Dedicated / internal builds are shipped already patched.
    if "internal" in (installed.suffix or "").lower():
        floor_hint = fixed_by_branch.get(installed.branch, "")
        return "PASS", floor_hint or installed.raw, "dedicated_internal_build"

    if min_affected:
        min_v = parse_version(min_affected)
        if min_v and _cmp_tuple(installed, min_v) < 0:
            return "PASS", "", "below_affected_range"

    # Closed advisory window (e.g. CVE-2026-97229 only ever hit 19.2–19.4).
    if max_affected:
        max_v = parse_version(max_affected)
        if max_v and (installed.major, installed.minor) > (max_v.major, max_v.minor):
            return "PASS", "", "not_in_affected_range"

    # Exact branch floor
    floor_text = fixed_by_branch.get(installed.branch)
    if floor_text:
        floor = parse_version(floor_text)
        if not floor:
            return "UNKNOWN", floor_text, "bad_floor_config"
        if is_at_least(installed, floor):
            return "PASS", floor.raw, "at_or_above_fixed"
        return "FAIL", floor.raw, "below_fixed"

    # Branch not listed: find highest branch <= installed and use that line's
    # semantics. For older lines without a floor entry under CVE-2026-110264,
    # anything from min_affected until first fixed branch is FAIL if the CVE
    # lists a catch-all (e.g. 18.11 floor covers 7.0–18.11.x via lowest listed).
    branches = []
    for b, f in fixed_by_branch.items():
        bp = parse_version(b)
        fp = parse_version(f)
        if bp and fp:
            branches.append((bp, fp))
    branches.sort(key=lambda x: x[0].as_tuple())

    if not branches:
        return "UNKNOWN", "", "empty_config"

    # If installed is on a line older than the oldest fixed branch entry,
    # use the oldest floor as the required upgrade target (FAIL).
    oldest_branch, oldest_floor = branches[0]
    if (installed.major, installed.minor) < (oldest_branch.major, oldest_branch.minor):
        return "FAIL", oldest_floor.raw, "no_backport"

    # Newer than newest listed branch, no closed max_affected → beyond known table.
    newest_branch, newest_floor = branches[-1]
    if (installed.major, installed.minor) > (newest_branch.major, newest_branch.minor):
        return "PASS", newest_floor.raw, "newer_than_table"

    # Same major.minor handled above; gap between listed branches:
    # pick the next higher listed branch as upgrade target.
    for bp, fp in branches:
        if (installed.major, installed.minor) <= (bp.major, bp.minor):
            return "FAIL", fp.raw, "between_listed_branches"
    return "UNKNOWN", "", "unhandled"


def go_exposure(installed_text: str, fixed_by_branch: dict[str, str]) -> tuple[str, str, str]:
    installed = parse_version(installed_text)
    if not installed:
        return "UNKNOWN", "", "unparseable"

    floor_text = fixed_by_branch.get(installed.branch)
    if floor_text:
        floor = parse_version(floor_text)
        if not floor:
            return "UNKNOWN", floor_text, "bad_floor_config"
        if is_at_least(installed, floor):
            return "PASS", floor.raw, "at_or_above_fixed"
        return "FAIL", floor.raw, "below_fixed"

    # Older than 1.26 → FAIL (no embedded distrust list)
    branches = sorted(
        ((parse_version(b), parse_version(f)) for b, f in fixed_by_branch.items()),
        key=lambda x: x[0].as_tuple() if x[0] else (0, 0, 0),
    )
    branches = [(b, f) for b, f in branches if b and f]
    if not branches:
        return "UNKNOWN", "", "empty_config"
    oldest_b, oldest_f = branches[0]
    if (installed.major, installed.minor) < (oldest_b.major, oldest_b.minor):
        return "FAIL", oldest_f.raw, "older_than_fixed_lines"
    newest_b, newest_f = branches[-1]
    if (installed.major, installed.minor) > (newest_b.major, newest_b.minor):
        return "PASS", newest_f.raw, "newer_than_table"
    return "UNKNOWN", "", "unknown_branch"


def certifi_exposure(installed_text: str, min_safe: str) -> tuple[str, str, str]:
    """Compare date-like certifi versions (YYYY.M.D or YYYY.MM.DD)."""
    try:
        installed = Version(installed_text.strip())
        floor = Version(min_safe.strip())
    except InvalidVersion:
        return "UNKNOWN", min_safe, "unparseable"
    if installed >= floor:
        return "PASS", min_safe, "at_or_above_fixed"
    return "FAIL", min_safe, "below_fixed"


def litellm_is_compromised(version_text: str, compromised: str = "1.107.0") -> bool:
    parsed = parse_version(version_text)
    target = parse_version(compromised)
    if not parsed or not target:
        # Fall back to exact string normalize
        return version_text.strip() == compromised.strip()
    return parsed.as_tuple() == target.as_tuple() and not parsed.suffix


def extract_php_version_from_banner(banner: str) -> str | None:
    """Parse PHP version from `php -v` or X-Powered-By: PHP/x.y.z."""
    if not banner:
        return None
    m = re.search(r"PHP[/ ](?P<v>\d+\.\d+(?:\.\d+)?(?:[-._][a-zA-Z0-9.+]+)?)", banner, re.I)
    if m:
        return m.group("v")
    parsed = parse_version(banner)
    return parsed.raw if parsed else None


def normalize_hash(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


def any_hash_match(digests: Iterable[str], compromised: Iterable[str]) -> str | None:
    compromised_set = {normalize_hash(h) for h in compromised}
    for d in digests:
        nd = normalize_hash(d)
        if nd in compromised_set:
            return nd
    return None

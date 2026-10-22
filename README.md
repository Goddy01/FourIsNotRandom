# cve-exposure-check

Detection-only CLI that fingerprints software versions and TLS/CA configuration to report exposure to a small set of currently relevant advisories.

> **This tool performs read-only version/fingerprint checks only. It does not exploit, does not send attack payloads, and must only be run against systems you own or are authorized to assess.**

## What it checks

| Area | Advisories | Detection methods |
|------|------------|-------------------|
| PHP | CVE-2026-109618, CVE-2026-109619 | Local `php -v`/`php -i`, HTTP headers, Docker/FS manifests, webroot app stacks |
| eMudhra CA | CVE-2026-111943 / related distrust | TLS chain digests, PEM/keystore files, Docker CA bundles, Go + certifi versions |
| GitLab | CVE-2026-110264, CVE-2026-97229 | Public `/help` or `/api/v4/version` (read-only) |
| LiteLLM | Malicious `1.107.0` release | Exact pin in pip env / requirements / lockfiles / Docker |

No CIDR sweeps: every run requires an explicit host, URL, path, image name, or a targets file of discrete entries.

## Install

```bash
python -m pip install -U pip
pip install -e ".[dev]"
cve-exposure-check --help
```

### Auditing this tool's own dependencies

Run `pip-audit` against the pinned requirements file — **not** bare `pip-audit`:

```bash
pip-audit -r requirements.txt
```

A bare `pip-audit` run audits your entire environment and will also flag the
venv's bootstrap `pip` package, which is unrelated to this tool's dependencies.
Use `pip-audit -r requirements.txt` so findings reflect only what this project
declares.

## Usage

```bash
# PHP
cve-exposure-check php --local
cve-exposure-check php --local --php-bin /usr/bin/php8.3
cve-exposure-check php --url https://example.com/
cve-exposure-check php --fs /var/www/html

# eMudhra / toolchains
cve-exposure-check emudhra --host example.com
cve-exposure-check emudhra --path /etc/ssl/certs
cve-exposure-check emudhra --docker my-image:tag
cve-exposure-check emudhra --toolchains

# GitLab (both CVSS 10.0 CVEs evaluated separately)
cve-exposure-check gitlab --url https://gitlab.example.com

# LiteLLM exact compromised pin
cve-exposure-check litellm --env
cve-exposure-check litellm --path .
cve-exposure-check litellm --docker ghcr.io/berriai/litellm:v1.107.0

# Explicit target list only (global flags before the subcommand)
cve-exposure-check --format json all --targets-file targets.txt
cve-exposure-check --format json emudhra toolchains
```

Exit codes: `0` = no FAIL, `1` = at least one FAIL, `2` = tool/config error.

## Advisory data (editable)

Bundled under `src/cve_exposure_check/data/`:

| File | Contents | How to refresh |
|------|----------|----------------|
| `fixed_versions.yaml` | PHP floors, GitLab per-CVE floors, Go floors, certifi floor, LiteLLM pin | Edit YAML; or pass `--config PATH` |
| `compromised_hashes.json` | Compromised eMudhra intermediate digests | Replace file or `cve-exposure-check update-hashes --from PATH` |
| `php_apps.yaml` | CMS/webroot path fingerprints | Edit YAML |

### Data provenance

- **PHP floors**: PHP project security releases (8.2.35, 8.3.36, 8.4.27, 8.5.12). Branches ≤8.1 have no upstream fix.
- **GitLab**: Official critical patch notes for CVE-2026-110264 (Oct 21) and CVE-2026-97229 (Oct 12). Both are reported separately so an Oct-12-only patch does not look “fully covered.”
- **eMudhra hashes**: Certificate SHA-256 fingerprints from Cisco Talos “Compromised eMudhra intermediate certificates” (Oct 21, 2026), citing Mozilla Bugzilla 2083449. The scanner matches **either** full-cert SHA-256 **or** SPKI SHA-256 against the configured set (Talos publishes cert fingerprints; Go’s CVE-2026-111943 fix matches SPKI — dual match avoids assuming hash type after a refresh).
- **certifi**: Floor `2026.10.18` (first release blocking compromised roots). `2026.10.19` restores some legitimate emSign roots (stability), not a security boundary.
- **Go**: Fixed in 1.27.3 / 1.26.10 (CVE-2026-111943).
- **LiteLLM**: Exact malicious PyPI/Docker release `1.107.0` only.

```bash
# Refresh eMudhra hash list from a JSON file with the same schema
cve-exposure-check update-hashes --from ./my-hashes.json
```

## Safety

> **Read-only / authorized use only.** This tool fingerprints versions and TLS/CA
> material. It does not exploit, does not send attack payloads, and must only be
> run against systems you own or are authorized to assess.

- Fingerprints only: versions, headers, banners, cert digests, read-only `php.ini` values.
- Does **not** send session.upload_progress exploits, memory-corruption probes, or any PoC payloads.
- Does **not** scan networks you did not name explicitly.
- Rejects CIDR ranges and bare wildcards — every target must be an explicit host, URL, or path.

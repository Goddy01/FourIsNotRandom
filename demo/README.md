# Local audit demo targets

Synthetic fixtures so you can exercise `cve-exposure-check` without scanning production.

## Quick run (filesystem / pins / certs)

```powershell
.\demo\run_demo.ps1
```

## Remote mocks (PHP headers + GitLab version)

Terminal A:

```powershell
.\.venv\Scripts\python demo\mock_server.py
```

Terminal B:

```powershell
.\demo\run_demo.ps1 -WithMock
```

Or one-off:

```powershell
cve-exposure-check php url http://127.0.0.1:8765/
cve-exposure-check php url http://127.0.0.1:8765/patched
cve-exposure-check gitlab --url http://127.0.0.1:8765
```

## What each fixture shows

| Path | Expected |
|------|----------|
| `vulnerable-php/` | FAIL — PHP 8.3.35 / 8.2.34 pins |
| `patched-php/` | PASS — PHP 8.3.36 |
| `webroot/` | FAIL PHP 8.4.26 + WordPress detected |
| `litellm-bad/` | FAIL — `litellm==1.107.0` |
| `litellm-ok/` | PASS — `1.106.2` |
| `certs/demo-bad.pem` + `demo-hashes.json` | FAIL — synthetic hash match |
| `certs/demo-clean.pem` | PASS against demo hashes |
| mock `/` | FAIL PHP 8.3.35 header |
| mock `/patched` | PASS PHP 8.3.36 header |
| mock GitLab `19.4.2` | PASS CVE-2026-97229, FAIL CVE-2026-110264 |

These are **demo artifacts only**, not real compromised CA material.

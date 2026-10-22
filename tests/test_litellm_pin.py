from pathlib import Path

from cve_exposure_check.checks.litellm import check_path
from cve_exposure_check.models import Status
from cve_exposure_check.versioning import litellm_is_compromised


def test_exact_compromised_only():
    assert litellm_is_compromised("1.107.0")
    assert not litellm_is_compromised("1.106.2")
    assert not litellm_is_compromised("1.107.1")


def test_requirements_file(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.32.0\nlitellm==1.107.0\n", encoding="utf-8")
    findings = check_path(tmp_path)
    assert any(f.status == Status.FAIL and "1.107.0" in f.installed for f in findings)

    req.write_text("litellm==1.106.2\n", encoding="utf-8")
    findings = check_path(tmp_path)
    assert all(f.status == Status.PASS for f in findings)

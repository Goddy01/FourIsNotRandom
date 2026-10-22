from cve_exposure_check.versioning import php_exposure

FIXED = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}


def test_php_below_fixed():
    assert php_exposure("8.3.35", FIXED)[0] == "FAIL"
    assert php_exposure("8.2.34", FIXED)[0] == "FAIL"
    assert php_exposure("8.4.26", FIXED)[0] == "FAIL"
    assert php_exposure("8.5.11", FIXED)[0] == "FAIL"


def test_php_at_or_above_fixed():
    assert php_exposure("8.3.36", FIXED)[0] == "PASS"
    assert php_exposure("8.3.37", FIXED)[0] == "PASS"
    assert php_exposure("8.2.35", FIXED)[0] == "PASS"
    assert php_exposure("8.5.12", FIXED)[0] == "PASS"


def test_php_eol_must_upgrade_major():
    status, _, reason = php_exposure("8.1.32", FIXED)
    assert status == "FAIL"
    assert reason == "eol_no_fix"
    status, _, reason = php_exposure("7.4.33", FIXED)
    assert status == "FAIL"
    assert reason == "eol_no_fix"


def test_php_unparseable():
    assert php_exposure("not-a-version", FIXED)[0] == "UNKNOWN"

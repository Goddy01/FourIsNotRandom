from cve_exposure_check.versioning import gitlab_exposure

CVE_110264 = {
    "18.11": "18.11.13",
    "19.0": "19.0.10",
    "19.1": "19.1.9",
    "19.2": "19.2.9",
    "19.3": "19.3.6",
    "19.4": "19.4.3",
    "19.5": "19.5.1",
}

CVE_97229 = {
    "19.2": "19.2.8",
    "19.3": "19.3.5",
    "19.4": "19.4.2",
}


def test_oct21_cve_requires_higher_than_oct12():
    # 19.4.2 patched Oct-12 CVE but NOT Oct-21 CVE
    assert gitlab_exposure("19.4.2", CVE_97229, min_affected="19.2")[0] == "PASS"
    assert gitlab_exposure("19.4.2", CVE_110264, min_affected="7.0")[0] == "FAIL"


def test_fully_patched_passes_both():
    assert gitlab_exposure("19.4.3", CVE_97229, min_affected="19.2")[0] == "PASS"
    assert gitlab_exposure("19.4.3", CVE_110264, min_affected="7.0")[0] == "PASS"
    assert gitlab_exposure("19.5.1", CVE_110264, min_affected="7.0")[0] == "PASS"


def test_old_gitlab_fails_110264():
    assert gitlab_exposure("15.0.0", CVE_110264, min_affected="7.0")[0] == "FAIL"
    assert gitlab_exposure("18.11.12", CVE_110264, min_affected="7.0")[0] == "FAIL"
    assert gitlab_exposure("18.11.13", CVE_110264, min_affected="7.0")[0] == "PASS"


def test_97229_below_affected_range_passes():
    assert gitlab_exposure("19.1.0", CVE_97229, min_affected="19.2")[0] == "PASS"


def test_97229_above_closed_window_not_in_affected_range():
    # 19.5+ / 20.x are confirmed outside the 19.2–19.4 window — not "beyond table".
    for ver in ("19.5.0", "19.5.1", "20.0.0"):
        status, _, reason = gitlab_exposure(
            ver, CVE_97229, min_affected="19.2", max_affected="19.4"
        )
        assert status == "PASS", ver
        assert reason == "not_in_affected_range", ver


def test_dedicated_internal_build_passes():
    status, _, reason = gitlab_exposure("19.3.5-internal0", CVE_110264, min_affected="7.0")
    assert status == "PASS"
    assert reason == "dedicated_internal_build"


def test_ancient_no_backport():
    status, _, reason = gitlab_exposure("7.14.2", CVE_110264, min_affected="7.0")
    assert status == "FAIL"
    assert reason == "no_backport"


def test_future_beyond_table_110264_only():
    # 110264 has no max_affected — 20.0.0 is genuinely beyond the known floor table.
    status, _, reason = gitlab_exposure("20.0.0", CVE_110264, min_affected="7.0")
    assert status == "PASS"
    assert reason == "newer_than_table"

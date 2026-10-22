from fourisnotrandom.versioning import (
    any_hash_match,
    certifi_exposure,
    extract_php_version_from_banner,
    go_exposure,
    litellm_is_compromised,
    parse_version,
)


def test_parse_version_basic():
    v = parse_version("8.3.35")
    assert v is not None
    assert v.as_tuple() == (8, 3, 35)


def test_extract_php_from_powered_by():
    assert extract_php_version_from_banner("X-Powered-By: PHP/8.2.34") == "8.2.34"
    assert extract_php_version_from_banner("PHP 8.4.26 (cli)") == "8.4.26"


def test_certifi_floor():
    assert certifi_exposure("2026.10.17", "2026.10.18")[0] == "FAIL"
    assert certifi_exposure("2026.10.18", "2026.10.18")[0] == "PASS"
    assert certifi_exposure("2026.10.19", "2026.10.18")[0] == "PASS"


def test_go_exposure():
    fixed = {"1.26": "1.26.10", "1.27": "1.27.3"}
    assert go_exposure("1.27.2", fixed)[0] == "FAIL"
    assert go_exposure("1.27.3", fixed)[0] == "PASS"
    assert go_exposure("1.26.10", fixed)[0] == "PASS"
    assert go_exposure("1.25.0", fixed)[0] == "FAIL"


def test_litellm_exact_pin():
    assert litellm_is_compromised("1.107.0") is True
    assert litellm_is_compromised("1.106.2") is False
    assert litellm_is_compromised("1.107.0rc1") is False


def test_hash_match_either_digest():
    compromised = {"aabbcc", "ddeeff"}
    assert any_hash_match(["00", "aabbcc"], compromised) == "aabbcc"
    assert any_hash_match(["aa:bb:cc"], compromised) == "aabbcc"
    assert any_hash_match(["zzzz"], compromised) is None

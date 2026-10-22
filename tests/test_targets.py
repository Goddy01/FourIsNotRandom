import pytest

from cve_exposure_check.targets import TargetError, assert_not_cidr_or_range


def test_rejects_cidr():
    with pytest.raises(TargetError):
        assert_not_cidr_or_range("10.0.0.0/24")
    with pytest.raises(TargetError):
        assert_not_cidr_or_range("192.168.1.0/16")
    with pytest.raises(TargetError):
        assert_not_cidr_or_range("10.0.0.1-10.0.0.50")


def test_rejects_wildcard():
    with pytest.raises(TargetError):
        assert_not_cidr_or_range("*")
    with pytest.raises(TargetError):
        assert_not_cidr_or_range("*.example.com")


def test_allows_single_host():
    assert assert_not_cidr_or_range("example.com") == "example.com"
    assert assert_not_cidr_or_range("https://gitlab.example.com") == "https://gitlab.example.com"
    assert assert_not_cidr_or_range("10.0.0.5") == "10.0.0.5"

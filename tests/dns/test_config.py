from dataclasses import replace

import pytest

from ingestion.dns.config import (
    AdGuardConfig,
    DNSConfigurationError,
    load_adguard_config,
)


@pytest.fixture
def config():
    return AdGuardConfig(
        base_url="https://dns.example.net",
        username="test-user",
        password="test-password",
    )


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    import os

    for key in os.environ:
        if key.startswith("ADGUARD_"):
            monkeypatch.delenv(key)


def test_environment_configuration(monkeypatch):
    monkeypatch.setenv("ADGUARD_URL", "https://dns.example.net/proxy/")
    monkeypatch.setenv("ADGUARD_USERNAME", "user")
    monkeypatch.setenv("ADGUARD_PASSWORD", "password")
    monkeypatch.setenv("ADGUARD_SOURCE_NAME", "office-dns")
    monkeypatch.setenv("ADGUARD_READ_TIMEOUT", "12.5")
    monkeypatch.setenv("ADGUARD_PAGE_SIZE", "250")
    config = load_adguard_config()
    assert config.source_name == "office-dns"
    assert config.read_timeout == 12.5
    assert config.page_size == 250
    assert config.connect_timeout == 5
    assert config.ca_bundle is None
    assert "password" not in repr(config)
    assert "user'" not in repr(config)


@pytest.mark.parametrize(
    "url",
    [
        "http://dns.example.net",
        "https://",
        "file:///tmp/dns",
        "https://user:password@dns.example.net",
        "https://dns.example.net?key=secret",
        "https://dns.example.net#secret",
        "https://dns.example.net:bad",
        "https://dns.example.net:0",
        "https://dns.example.net:65536",
        "https://dns.example.net/ bad",
        "https://dns.example.net/\nsecret",
    ],
)
def test_reject_unsafe_urls(config, url):
    with pytest.raises(DNSConfigurationError) as error:
        replace(config, base_url=url)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("connect_timeout", 0),
        ("read_timeout", -1),
        ("read_timeout", float("inf")),
        ("read_timeout", float("nan")),
        ("read_timeout", 301),
        ("connect_timeout", True),
        ("page_size", 0),
        ("page_size", 1001),
        ("page_size", True),
        ("source_name", ""),
        ("source_name", "two words"),
        ("username", ""),
        ("username", "user:name"),
        ("password", ""),
        ("password", "not-latin-1-\u2603"),
    ],
)
def test_invalid_settings(config, field, value):
    with pytest.raises(DNSConfigurationError):
        replace(config, **{field: value})


def test_missing_environment_is_safe():
    with pytest.raises(DNSConfigurationError, match="environment settings"):
        load_adguard_config()


def test_invalid_numeric_environment_is_safe(monkeypatch):
    monkeypatch.setenv("ADGUARD_URL", "https://dns.example.net")
    monkeypatch.setenv("ADGUARD_USERNAME", "user")
    monkeypatch.setenv("ADGUARD_PASSWORD", "secret-value")
    monkeypatch.setenv("ADGUARD_READ_TIMEOUT", "secret-value")
    with pytest.raises(DNSConfigurationError) as error:
        load_adguard_config()
    assert "secret-value" not in str(error.value)


def test_custom_ca_path(config, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("test fixture, not a certificate")
    assert replace(config, ca_bundle=str(ca)).ca_bundle == str(ca)
    with pytest.raises(DNSConfigurationError):
        replace(config, ca_bundle=str(tmp_path))
    with pytest.raises(DNSConfigurationError):
        replace(config, ca_bundle=str(tmp_path / "missing.pem"))


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_pages", 0),
        ("max_seconds", 241),
        ("overlap_seconds", -1),
        ("settle_seconds", True),
        ("max_group_events", 40001),
        ("retention_days", 0),
    ],
)
def test_collector_limits(name, value):
    from ingestion.dns.config import CollectorConfig

    with pytest.raises(DNSConfigurationError):
        CollectorConfig(**{name: value})


def test_collector_environment(monkeypatch):
    from ingestion.dns.config import load_collector_config

    monkeypatch.setenv("DNS_MAX_PAGES", "250")
    assert load_collector_config().max_pages == 250
    monkeypatch.setenv("DNS_MAX_PAGES", "secret-value")
    with pytest.raises(DNSConfigurationError) as error:
        load_collector_config()
    assert "secret-value" not in str(error.value)

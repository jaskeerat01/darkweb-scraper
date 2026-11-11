from scraper.config import Config
from scraper.network.policy import (
    TargetKind,
    domain_allowed,
    is_allowed_target_url,
    is_onion_host,
    network_label,
    target_kind,
)


def _clearnet_config(**overrides):
    values = {
        "allow_clearnet_targets": True,
        "clearnet_allowed_domains": ("example.com",),
        "clearnet_allow_any": False,
    }
    values.update(overrides)
    return Config(**values)


def test_onion_targets_are_always_in_scope():
    assert is_allowed_target_url(
        "http://abcdefghijklmnop.onion/thread-1", Config()
    )
    assert target_kind("https://x.onion/") is TargetKind.ONION
    assert is_onion_host("WWW.Example.ONION.") is True
    assert network_label("abcdef.onion") == "onion"


def test_clearnet_is_disabled_by_default():
    assert not is_allowed_target_url("https://example.com/security", Config())


def test_clearnet_requires_scope_even_when_enabled():
    config = Config(allow_clearnet_targets=True)
    assert not is_allowed_target_url("https://example.com/security", config)


def test_clearnet_allowlist_matches_exact_and_subdomains():
    config = _clearnet_config()
    assert is_allowed_target_url("https://example.com/security", config)
    assert is_allowed_target_url("https://news.example.com/", config)
    assert not is_allowed_target_url("https://example.net/", config)
    assert domain_allowed("news.example.com", ("example.com",))


def test_clearnet_allow_any_is_explicit():
    config = Config(allow_clearnet_targets=True, clearnet_allow_any=True)
    assert is_allowed_target_url("https://example.net/", config)


def test_private_and_local_hosts_are_rejected():
    config = Config(allow_clearnet_targets=True, clearnet_allow_any=True)
    for url in (
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://service.local/",
        "http://printer/",
        "http://[::1]/",
        "http://2130706433/",
        "http://0x7f000001/",
    ):
        assert not is_allowed_target_url(url, config), url


def test_ports_https_and_credentials_are_enforced():
    config = _clearnet_config()
    assert not is_allowed_target_url("https://example.com:8443/", config)
    assert is_allowed_target_url("https://example.com:443/", config)

    https_only = _clearnet_config(clearnet_require_https=True)
    assert not is_allowed_target_url("http://example.com/", https_only)
    assert is_allowed_target_url("https://example.com/", https_only)

    assert not is_allowed_target_url("https://user:pass@example.com/", config)
    assert not is_allowed_target_url("ftp://example.com/", config)

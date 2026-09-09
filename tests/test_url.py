from scraper.parsers.url import (
    is_onion_url,
    normalize_hostname,
    normalize_page_url,
    is_allowed_page_url,
)
from scraper.parsers.heuristics import score_page_url


def test_is_onion_url():
    assert is_onion_url("http://breached4wtyw5fb45zj7sggnoazgv3aohme2zftkrndhvo76d5q5uad.onion/view.php")
    assert not is_onion_url("https://google.com")
    assert not is_onion_url("http://onion.clearnet-mirror.com")


def test_normalize_hostname():
    assert normalize_hostname("www.example.onion") == "example.onion"
    assert normalize_hostname("EXAMPLE.ONION") == "example.onion"


def test_normalize_page_url_strips_noise():
    raw = "http://target.onion/view.php?sid=abc12345&s=xyz&page=1&topic=42"
    normalized = normalize_page_url(raw)
    assert "sid=" not in normalized
    assert "s=" not in normalized
    assert "page=1" not in normalized
    assert "topic=42" in normalized


def test_is_allowed_page_url():
    assert is_allowed_page_url("http://target.onion/thread-100.html")
    # Ignored extensions
    assert not is_allowed_page_url("http://target.onion/archive.zip")
    assert not is_allowed_page_url("http://target.onion/avatar.png")
    # Noise paths
    assert not is_allowed_page_url("http://target.onion/user/profile.php")
    assert not is_allowed_page_url("http://target.onion/login")


def test_score_page_url():
    leak_score = score_page_url("http://target.onion/database-leak-2026.html", "Breach database")
    login_score = score_page_url("http://target.onion/wp-login.php", "Sign in")
    assert leak_score > 0
    assert login_score < 0
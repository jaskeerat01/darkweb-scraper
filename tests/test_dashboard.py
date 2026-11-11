import pytest
from fastapi.testclient import TestClient

from scraper.config import Config
from scraper.dashboard.app import create_app
from scraper.dashboard.db import query_only_guard
from scraper.dashboard.settings import DashboardConfigError, DashboardSettings
from scraper.storage.db import init_db
from scraper.storage.repositories import AlertRepository

HOSTS = ("testserver", "localhost", "127.0.0.1")


def _settings(db, **overrides):
    values = {"db_path": db, "allowed_hosts": HOSTS}
    values.update(overrides)
    return DashboardSettings(**values)


def _seed(db):
    init_db(str(db))
    config = Config(db_path=str(db))
    assert AlertRepository.save_if_new(
        "BreachForums",
        "http://abc.onion/thread-1",
        "LockBit",
        "A database leak with customer records and <script>alert('x')</script>",
        "a" * 64,
        "data_leak",
        [],
        ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "t.me/actor"],
        "LockBit claims the Acme breach.",
        "high",
        db,
        config=config,
    )
    assert AlertRepository.save_if_new(
        "Example News",
        "https://example.com/post",
        "Example",
        "A normal marketplace listing",
        "b" * 64,
        "marketplace",
        [],
        [],
        "",
        "low",
        db,
        config=config,
    )


def test_empty_database_renders_onboarding(tmp_path):
    settings = _settings(tmp_path / "missing.db")
    client = TestClient(create_app(settings))
    response = client.get("/")
    assert response.status_code == 200
    assert "No alerts database yet" in response.text
    assert client.get("/healthz").status_code == 503


def test_alert_list_detail_and_escaping(temp_db):
    _seed(temp_db)
    client = TestClient(create_app(_settings(temp_db)))

    response = client.get("/")
    assert response.status_code == 200
    assert "LockBit claims the Acme breach." in response.text
    assert "<script>alert" not in response.text
    assert "sev-high" in response.text
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in response.text

    detail = client.get("/alerts/1")
    assert detail.status_code == 200
    assert "LockBit claims the Acme breach." in detail.text
    assert "Indicators" not in detail.text  # panel labels are lower-case
    assert "indicators" in detail.text

    missing = client.get("/alerts/999")
    assert missing.status_code == 404


def test_filters_and_api(temp_db):
    _seed(temp_db)
    client = TestClient(create_app(_settings(temp_db)))

    filtered = client.get("/?severity=high&network=onion")
    assert filtered.status_code == 200
    assert "BreachForums" in filtered.text
    assert filtered.text.count('class="alert-row"') == 1

    search = client.get("/?q=marketplace")
    assert "Example News" in search.text
    assert search.text.count('class="alert-row"') == 1

    api = client.get("/api/alerts?severity=high").json()
    assert api["total"] == 1
    assert api["alerts"][0]["severity"] == "high"

    stats = client.get("/api/stats").json()
    assert stats["total"] == 2
    assert stats["onion"] == 1
    assert stats["clearnet"] == 1

    since = client.get("/api/alerts?since=0").json()
    assert since["count"] == 2

    invalid = client.get("/?severity=urgent")
    assert invalid.status_code == 400


def test_security_headers(temp_db):
    _seed(temp_db)
    response = TestClient(create_app(_settings(temp_db))).get("/")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_read_only_database_guard(temp_db):
    query_only_guard(temp_db)


def test_auth_flow_and_rate_limit(temp_db):
    _seed(temp_db)
    settings = _settings(temp_db, auth_token="secret-token")
    client = TestClient(create_app(settings))

    unauthenticated = client.get("/", follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert "/login" in unauthenticated.headers["location"]

    wrong = client.post("/login", data={"token": "wrong", "next": "/"})
    assert wrong.status_code == 401

    good = client.post(
        "/login", data={"token": "secret-token", "next": "/"}, follow_redirects=False
    )
    assert good.status_code == 303
    assert "dwi_session" in client.cookies

    assert client.get("/").status_code == 200
    assert client.post("/logout", follow_redirects=False).status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_non_loopback_without_token_is_refused():
    with pytest.raises(DashboardConfigError):
        _settings("data/alerts.db", host="0.0.0.0").validate()


def test_unknown_host_is_rejected(temp_db):
    client = TestClient(create_app(_settings(temp_db)))
    response = client.get("/", headers={"Host": "evil.example"})
    assert response.status_code == 400

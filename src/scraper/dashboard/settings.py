"""Dashboard-only settings.

The dashboard intentionally reads only ``DB_PATH`` and ``DASHBOARD_*`` keys.
It never imports ``scraper.config`` and never loads Tor or Telegram secrets into
its process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from dotenv import dotenv_values

PROJECT_ROOT = next(
    (
        candidate
        for candidate in Path(__file__).resolve().parents
        if (candidate / "pyproject.toml").exists()
    ),
    Path.cwd(),
)

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}


class DashboardConfigError(ValueError):
    """Raised for unsafe or malformed dashboard configuration."""


def _bool(values: Mapping[str, str], name: str, default: bool) -> bool:
    raw = values.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise DashboardConfigError(f"{name} must be a boolean")


def _int(
    values: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise DashboardConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise DashboardConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _csv(values: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = values.get(name)
    if raw is None or not raw.strip():
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _is_loopback(host: str) -> bool:
    value = host.strip().lower().strip("[]")
    return value in {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True, slots=True)
class DashboardSettings:
    db_path: Path
    host: str = "127.0.0.1"
    port: int = 8787
    auth_token: str | None = None
    secure_cookie: bool = False
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")
    page_size: int = 25
    poll_seconds: int = 15
    access_log: bool = False
    enable_docs: bool = False

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_token)

    @property
    def loopback_only(self) -> bool:
        return _is_loopback(self.host)

    def validate(self) -> None:
        if not self.loopback_only and not self.auth_enabled:
            raise DashboardConfigError(
                "Refusing to bind the dashboard to a non-loopback address without "
                "DASHBOARD_AUTH_TOKEN. Use a reverse proxy with authentication or "
                "bind 127.0.0.1."
            )
        if not self.loopback_only and self.auth_enabled and not self.secure_cookie:
            raise DashboardConfigError(
                "Non-loopback dashboards must use DASHBOARD_SECURE_COOKIE=true "
                "behind TLS. Bind 127.0.0.1 for local HTTP access."
            )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        env_file: str | Path | None = None,
    ) -> "DashboardSettings":
        file_values: dict[str, str] = {}
        runtime_env = dict(os.environ if env is None else env)
        candidate_value = env_file or runtime_env.get("DASHBOARD_ENV_FILE")
        if candidate_value:
            candidate = Path(candidate_value)
        elif any(
            key == "DB_PATH" or key.startswith("DASHBOARD_")
            for key in runtime_env
        ):
            # A service manager already supplied the dashboard settings; do not
            # read the scraper's .env and its unrelated secrets.
            candidate = None
        else:
            candidate = PROJECT_ROOT / ".env"

        if candidate is not None and candidate.exists():
            # dotenv_values does not mutate os.environ. Filter to the keys this
            # process needs so unrelated secrets are never retained in memory.
            file_values = {
                str(key): str(value)
                for key, value in dotenv_values(candidate).items()
                if value is not None
                and (str(key) == "DB_PATH" or str(key).startswith("DASHBOARD_"))
            }
        merged = {**file_values, **runtime_env}

        raw_db = (
            merged.get("DASHBOARD_DB_PATH")
            or merged.get("DB_PATH")
            or "data/alerts.db"
        ).strip()
        db_path = Path(raw_db).expanduser()
        if not db_path.is_absolute():
            db_path = PROJECT_ROOT / db_path

        host = (merged.get("DASHBOARD_HOST") or "127.0.0.1").strip()
        port = _int(merged, "DASHBOARD_PORT", 8787, minimum=1, maximum=65535)
        token = (merged.get("DASHBOARD_AUTH_TOKEN") or "").strip() or None
        allowed = _csv(
            merged,
            "DASHBOARD_ALLOWED_HOSTS",
            ("127.0.0.1", "localhost", "::1"),
        )

        settings = cls(
            db_path=db_path,
            host=host,
            port=port,
            auth_token=token,
            secure_cookie=_bool(merged, "DASHBOARD_SECURE_COOKIE", False),
            allowed_hosts=allowed,
            page_size=_int(merged, "DASHBOARD_PAGE_SIZE", 25, minimum=5, maximum=100),
            poll_seconds=_int(merged, "DASHBOARD_POLL_SECONDS", 15, minimum=5, maximum=120),
            access_log=_bool(merged, "DASHBOARD_ACCESS_LOG", False),
            enable_docs=_bool(merged, "DASHBOARD_ENABLE_DOCS", False),
        )
        settings.validate()
        return settings

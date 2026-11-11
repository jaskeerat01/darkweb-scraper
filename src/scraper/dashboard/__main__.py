"""Standalone dashboard entrypoint: ``python -m scraper.dashboard``."""

from __future__ import annotations

import argparse
from dataclasses import replace

import uvicorn

from scraper.dashboard.app import create_app
from scraper.dashboard.settings import DashboardConfigError, DashboardSettings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="darkweb-dashboard",
        description="Read-only local alert dashboard for the Dark Web Threat Intelligence Engine.",
    )
    parser.add_argument("--host", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Bind port (default: 8787)")
    parser.add_argument("--db", help="Path to alerts.db (default: DB_PATH)")
    parser.add_argument(
        "--secure-cookie",
        action="store_true",
        help="Mark the session cookie Secure (use behind an HTTPS reverse proxy)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = DashboardSettings.from_env()
        overrides = {}
        if args.host:
            overrides["host"] = args.host
        if args.port:
            overrides["port"] = args.port
        if args.db:
            from pathlib import Path

            overrides["db_path"] = Path(args.db).expanduser().resolve()
        if args.secure_cookie:
            overrides["secure_cookie"] = True
        if overrides:
            settings = replace(settings, **overrides)
            settings.validate()
    except DashboardConfigError as exc:
        print(f"Dashboard configuration error: {exc}")
        return 2

    app = create_app(settings)
    print(f"Dashboard: http://{settings.host}:{settings.port}")
    if settings.auth_enabled:
        print("Authentication: enabled (DASHBOARD_AUTH_TOKEN)")
    else:
        print("Authentication: disabled (loopback only)")

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=settings.access_log,
        server_header=False,
        proxy_headers=False,
        workers=1,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""FastAPI application factory for the read-only alert dashboard."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scraper.dashboard.db import database_status, read_only_connection
from scraper.dashboard.queries import (
    FilterError,
    Filters,
    get_alert,
    get_filter_options,
    get_latest_timestamp,
    get_sites,
    get_stats,
    list_alerts,
    list_new_alerts,
)
from scraper.dashboard.security import (
    COOKIE_NAME,
    SECURITY_HEADERS,
    SESSION_TTL_SECONDS,
    LoginRateLimiter,
    sign_session,
    tokens_match,
    verify_session,
)
from scraper.dashboard.settings import DashboardSettings

logger = logging.getLogger("scraper.dashboard")

PACKAGE_DIR = Path(__file__).resolve().parent


def _utc(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (TypeError, ValueError, OSError):
        return "—"


def _utc_date(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return "—"


def _relative(value: Any) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return "—"
    now = datetime.now(timezone.utc).timestamp()
    delta = max(0, int(now - timestamp))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "\n" in value or "\r" in value:
        return "/"
    return value


def _query_string(filters: Filters, cursor: tuple[int, int] | None = None) -> str:
    pairs = filters.query_pairs()
    if cursor:
        pairs.append(("cursor", f"{cursor[0]}:{cursor[1]}"))
    return urlencode(pairs)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(settings: DashboardSettings | None = None) -> FastAPI:
    cfg = settings or DashboardSettings.from_env()
    cfg.validate()

    app = FastAPI(
        title="Dark Web Intel",
        docs_url="/docs" if cfg.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if cfg.enable_docs else None,
    )
    app.state.settings = cfg
    app.state.login_limiter = LoginRateLimiter()

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(cfg.allowed_hosts) or ["127.0.0.1", "localhost"],
    )

    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
    templates.env.filters["utc"] = _utc
    templates.env.filters["utc_date"] = _utc_date
    templates.env.filters["relative"] = _relative

    app.mount(
        "/static",
        StaticFiles(directory=str(PACKAGE_DIR / "static")),
        name="static",
    )

    def render(
        request: Request,
        name: str,
        context: dict[str, Any],
        *,
        status_code: int = 200,
    ) -> HTMLResponse:
        base = {
            "request": request,
            "auth_enabled": cfg.auth_enabled,
            "local_only": cfg.loopback_only,
            "poll_seconds": cfg.poll_seconds,
            "latest_ts": 0,
            "poll_enabled": False,
        }
        base.update(context)
        return templates.TemplateResponse(
            request=request,
            name=name,
            context=base,
            status_code=status_code,
        )

    @app.middleware("http")
    async def auth_and_headers(request: Request, call_next):
        path = request.url.path
        exempt = (
            path == "/login"
            or path == "/healthz"
            or path.startswith("/static/")
        )
        if cfg.auth_enabled and not exempt:
            if not verify_session(request.cookies.get(COOKIE_NAME), cfg.auth_token):
                if path.startswith("/api/") or path == "/healthz":
                    response: Response = JSONResponse(
                        {"error": "authentication required"}, status_code=401
                    )
                else:
                    target = path
                    if request.url.query:
                        target = f"{target}?{request.url.query}"
                    response = RedirectResponse(
                        f"/login?next={quote(target)}", status_code=303
                    )
                for header, value in SECURITY_HEADERS.items():
                    response.headers.setdefault(header, value)
                return response

        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    # ------------------------------------------------------------------ pages
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        try:
            filters = Filters.from_params(
                request.query_params, page_size=cfg.page_size
            )
        except FilterError as exc:
            return render(
                request,
                "error.html",
                {"message": str(exc), "status": 400},
                status_code=400,
            )

        available, reason = database_status(cfg.db_path)
        filters_active = any(
            (
                filters.q,
                filters.severity,
                filters.category,
                filters.source,
                filters.network,
                filters.date_from,
                filters.date_to,
            )
        )
        base_context: dict[str, Any] = {
            "filters": filters,
            "filters_active": filters_active,
            "active": "alerts",
            "db_available": available,
            "db_error": reason,
            "alerts": [],
            "total": 0,
            "stats": {
                "total": 0,
                "today": 0,
                "last_24h": 0,
                "high_7d": 0,
                "onion": 0,
                "clearnet": 0,
                "sites_up": 0,
                "sites_down": 0,
                "sites_unknown": 0,
                "top_categories": [],
            },
            "categories": [],
            "sources": [],
            "next_url": None,
            "reset_url": "/",
            "poll_enabled": False,
        }
        if not available:
            return render(request, "index.html", base_context)

        try:
            with read_only_connection(cfg.db_path) as conn:
                page = list_alerts(conn, filters)
                stats = get_stats(conn)
                options = get_filter_options(conn)
                latest_ts = get_latest_timestamp(conn)
        except Exception as exc:
            logger.warning("Dashboard read failed: %s", type(exc).__name__)
            base_context["db_available"] = False
            base_context["db_error"] = "database unavailable"
            return render(request, "index.html", base_context)

        next_url = None
        if page.next_cursor:
            next_url = f"/?{_query_string(filters, page.next_cursor)}"

        base_context.update(
            {
                "alerts": page.rows,
                "total": page.total,
                "stats": stats,
                "categories": options["categories"],
                "sources": options["sources"],
                "next_url": next_url,
                "reset_url": "/",
                "latest_ts": latest_ts,
                "poll_enabled": True,
            }
        )
        return render(request, "index.html", base_context)

    @app.get("/alerts/{alert_id:int}", response_class=HTMLResponse)
    def alert_detail(request: Request, alert_id: int):
        available, reason = database_status(cfg.db_path)
        if not available:
            return render(
                request,
                "error.html",
                {"message": "The alerts database is not available.", "status": 503},
                status_code=503,
            )
        try:
            with read_only_connection(cfg.db_path) as conn:
                alert = get_alert(conn, alert_id)
        except Exception:
            logger.exception("Failed to read alert %s", alert_id)
            alert = None

        if alert is None:
            return render(
                request,
                "error.html",
                {"message": "Alert not found.", "status": 404},
                status_code=404,
            )
        return render(
            request,
            "alert.html",
            {
                "active": "alerts",
                "alert": alert,
                "latest_ts": alert["timestamp"],
                "poll_enabled": True,
            },
        )

    @app.get("/sources", response_class=HTMLResponse)
    def sources(request: Request):
        available, reason = database_status(cfg.db_path)
        sites: list[dict[str, Any]] = []
        stats = {"sites_up": 0, "sites_down": 0, "sites_unknown": 0}
        if available:
            try:
                with read_only_connection(cfg.db_path) as conn:
                    sites = get_sites(conn)
                    stats = get_stats(conn)
            except Exception:
                logger.exception("Failed to read site health")
                available = False
                reason = "database unavailable"
        return render(
            request,
            "sources.html",
            {
                "active": "sources",
                "db_available": available,
                "db_error": reason,
                "sites": sites,
                "stats": stats,
            },
        )

    @app.get("/about", response_class=HTMLResponse)
    def about(request: Request):
        return render(request, "about.html", {"active": "about"})

    # -------------------------------------------------------------------- API
    @app.get("/api/alerts")
    def api_alerts(request: Request):
        try:
            filters = Filters.from_params(
                request.query_params, page_size=cfg.page_size
            )
        except FilterError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        available, _reason = database_status(cfg.db_path)
        if not available:
            return JSONResponse({"error": "database unavailable"}, status_code=503)

        since_raw = request.query_params.get("since")
        try:
            with read_only_connection(cfg.db_path) as conn:
                if since_raw:
                    try:
                        since = int(since_raw)
                    except ValueError:
                        return JSONResponse({"error": "invalid since"}, status_code=400)
                    rows = list_new_alerts(conn, since, filters)
                    latest = max((row["timestamp"] for row in rows), default=since)
                    return JSONResponse(
                        {"alerts": rows, "latest": latest, "count": len(rows)}
                    )
                page = list_alerts(conn, filters)
        except Exception as exc:
            logger.warning("API alert query failed: %s", type(exc).__name__)
            return JSONResponse({"error": "database unavailable"}, status_code=503)

        return JSONResponse(
            {
                "alerts": page.rows,
                "total": page.total,
                "next_cursor": (
                    f"{page.next_cursor[0]}:{page.next_cursor[1]}"
                    if page.next_cursor
                    else None
                ),
            }
        )

    @app.get("/api/alerts/{alert_id:int}")
    def api_alert(alert_id: int):
        available, _reason = database_status(cfg.db_path)
        if not available:
            return JSONResponse({"error": "database unavailable"}, status_code=503)
        try:
            with read_only_connection(cfg.db_path) as conn:
                alert = get_alert(conn, alert_id)
        except Exception:
            logger.warning("API alert read failed", exc_info=True)
            return JSONResponse({"error": "database unavailable"}, status_code=503)
        if alert is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(alert)

    @app.get("/api/stats")
    def api_stats():
        available, _reason = database_status(cfg.db_path)
        if not available:
            return JSONResponse({"error": "database unavailable"}, status_code=503)
        try:
            with read_only_connection(cfg.db_path) as conn:
                return JSONResponse(get_stats(conn))
        except Exception:
            logger.warning("API stats read failed", exc_info=True)
            return JSONResponse({"error": "database unavailable"}, status_code=503)

    @app.get("/api/sites")
    def api_sites():
        available, _reason = database_status(cfg.db_path)
        if not available:
            return JSONResponse({"error": "database unavailable"}, status_code=503)
        try:
            with read_only_connection(cfg.db_path) as conn:
                return JSONResponse({"sites": get_sites(conn)})
        except Exception:
            logger.warning("API sites read failed", exc_info=True)
            return JSONResponse({"error": "database unavailable"}, status_code=503)

    @app.get("/healthz")
    def healthz():
        available, reason = database_status(cfg.db_path)
        return JSONResponse(
            {"status": "ok" if available else "degraded", "database": reason},
            status_code=200 if available else 503,
        )

    # ------------------------------------------------------------------ login
    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        if not cfg.auth_enabled:
            return RedirectResponse("/", status_code=303)
        if verify_session(request.cookies.get(COOKIE_NAME), cfg.auth_token):
            return RedirectResponse(_safe_next(request.query_params.get("next")), status_code=303)
        return render(
            request,
            "login.html",
            {"next": _safe_next(request.query_params.get("next")), "error": None},
        )

    @app.post("/login")
    async def login_submit(request: Request):
        if not cfg.auth_enabled:
            return RedirectResponse("/", status_code=303)

        key = _client_key(request)
        limiter: LoginRateLimiter = app.state.login_limiter
        if not limiter.allowed(key):
            return render(
                request,
                "login.html",
                {
                    "next": "/",
                    "error": "Too many attempts. Try again in a minute.",
                },
                status_code=429,
            )

        origin = request.headers.get("origin")
        if origin:
            expected_host = request.headers.get("host", "")
            if origin.split("://")[-1] != expected_host:
                return render(
                    request,
                    "login.html",
                    {"next": "/", "error": "Invalid request origin."},
                    status_code=403,
                )

        body = (await request.body()).decode("utf-8", errors="ignore")
        form = parse_qs(body)
        candidate = (form.get("token") or [""])[0]
        next_url = _safe_next((form.get("next") or ["/"])[0])

        if not tokens_match(candidate, cfg.auth_token or ""):
            limiter.record_failure(key)
            return render(
                request,
                "login.html",
                {"next": next_url, "error": "Invalid access token."},
                status_code=401,
            )

        limiter.reset(key)
        response = RedirectResponse(next_url, status_code=303)
        response.set_cookie(
            COOKIE_NAME,
            sign_session(cfg.auth_token or ""),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            secure=cfg.secure_cookie,
            path="/",
        )
        return response

    @app.post("/logout")
    def logout():
        response = RedirectResponse("/login" if cfg.auth_enabled else "/", status_code=303)
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    # ----------------------------------------------------------------- errors
    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "not found"}, status_code=404)
        return render(
            request,
            "error.html",
            {"message": "Page not found.", "status": 404},
            status_code=404,
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc):
        logger.exception("Unhandled dashboard error")
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "internal server error"}, status_code=500)
        return render(
            request,
            "error.html",
            {"message": "An internal error occurred.", "status": 500},
            status_code=500,
        )

    return app

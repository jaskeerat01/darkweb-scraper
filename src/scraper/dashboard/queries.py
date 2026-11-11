"""Parameterised, read-only alert queries for the dashboard."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Mapping

from scraper.network.policy import host_from_url, network_label


class FilterError(ValueError):
    """Raised for invalid or unsafe user-supplied filters."""


@dataclass(frozen=True, slots=True)
class Filters:
    q: str = ""
    severity: str | None = None
    category: str | None = None
    source: str | None = None
    network: str | None = None
    date_from: date | None = None
    date_to: date | None = None
    limit: int = 25
    cursor: tuple[int, int] | None = None

    @classmethod
    def from_params(
        cls,
        params: Mapping[str, str],
        *,
        page_size: int = 25,
    ) -> "Filters":
        q = (params.get("q") or "").strip()[:120]
        severity = (params.get("severity") or "").strip().lower() or None
        if severity is not None and severity not in {"high", "medium", "low"}:
            raise FilterError("invalid severity")
        category = (params.get("category") or "").strip()[:80] or None
        source = (params.get("source") or "").strip()[:200] or None
        network = (params.get("network") or "").strip().lower() or None
        if network is not None and network not in {"onion", "clearnet"}:
            raise FilterError("invalid network")

        date_from = _parse_date(params.get("from"), "from")
        date_to = _parse_date(params.get("to"), "to")
        if date_from and date_to and date_from > date_to:
            raise FilterError("from must be before to")

        try:
            limit = int(params.get("limit") or page_size)
        except ValueError as exc:
            raise FilterError("invalid limit") from exc
        limit = max(1, min(limit, 100))

        cursor = None
        raw_cursor = (params.get("cursor") or "").strip()
        if raw_cursor:
            parts = raw_cursor.split(":")
            if len(parts) == 2:
                try:
                    cursor = (int(parts[0]), int(parts[1]))
                except ValueError as exc:
                    raise FilterError("invalid cursor") from exc

        return cls(
            q=q,
            severity=severity,
            category=category,
            source=source,
            network=network,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            cursor=cursor,
        )

    def query_pairs(self, *, include_cursor: bool = False) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if self.q:
            pairs.append(("q", self.q))
        if self.severity:
            pairs.append(("severity", self.severity))
        if self.category:
            pairs.append(("category", self.category))
        if self.source:
            pairs.append(("source", self.source))
        if self.network:
            pairs.append(("network", self.network))
        if self.date_from:
            pairs.append(("from", self.date_from.isoformat()))
        if self.date_to:
            pairs.append(("to", self.date_to.isoformat()))
        if include_cursor and self.cursor:
            pairs.append(("cursor", f"{self.cursor[0]}:{self.cursor[1]}"))
        return pairs


@dataclass(slots=True)
class AlertPage:
    rows: list[dict[str, Any]]
    total: int
    next_cursor: tuple[int, int] | None


def _parse_date(raw: str | None, field: str) -> date | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(raw.strip())
    except ValueError as exc:
        raise FilterError(f"invalid {field} date") from exc


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped.lower()}%"


def _where(filters: Filters, *, include_cursor: bool = True) -> tuple[str, list[Any]]:
    clauses: list[str] = ["1 = 1"]
    params: list[Any] = []

    if filters.q:
        pattern = _like(filters.q)
        clauses.append(
            "(LOWER(COALESCE(summary, '')) LIKE ? ESCAPE '\\' "
            "OR LOWER(COALESCE(description, '')) LIKE ? ESCAPE '\\' "
            "OR LOWER(COALESCE(source_name, '')) LIKE ? ESCAPE '\\' "
            "OR LOWER(COALESCE(iocs, '')) LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern, pattern, pattern, pattern])
    if filters.severity:
        clauses.append("COALESCE(severity, 'low') = ?")
        params.append(filters.severity)
    if filters.category:
        clauses.append("COALESCE(category, 'other') = ?")
        params.append(filters.category)
    if filters.source:
        clauses.append("source_name = ?")
        params.append(filters.source)
    if filters.network == "onion":
        clauses.append("source_host LIKE '%.onion'")
    elif filters.network == "clearnet":
        clauses.append("source_host NOT LIKE '%.onion'")
    if filters.date_from:
        start = datetime.combine(
            filters.date_from, datetime.min.time(), tzinfo=timezone.utc
        )
        clauses.append("timestamp >= ?")
        params.append(int(start.timestamp()))
    if filters.date_to:
        end = datetime.combine(
            filters.date_to + timedelta(days=1),
            datetime.min.time(),
            tzinfo=timezone.utc,
        )
        clauses.append("timestamp < ?")
        params.append(int(end.timestamp()))

    if include_cursor and filters.cursor:
        clauses.append("(timestamp < ? OR (timestamp = ? AND id < ?))")
        params.extend([filters.cursor[0], filters.cursor[0], filters.cursor[1]])

    return " AND ".join(clauses), params


def parse_iocs(raw: Any) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))][:50]


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    iocs = parse_iocs(data.get("iocs"))
    snippet = (data.get("snippet") or "").strip()
    summary = (data.get("summary") or "").strip()
    data["iocs_list"] = iocs
    data["entities_list"] = parse_iocs(data.get("entities"))
    data["snippet"] = snippet
    data["description_display"] = snippet
    data["display_summary"] = summary or snippet or "(no summary available)"
    data["severity"] = (data.get("severity") or "low").lower()
    data["category"] = data.get("category") or "other"
    data["network"] = network_label(data.get("source_host"))
    return data


def list_alerts(conn: sqlite3.Connection, filters: Filters) -> AlertPage:
    where, params = _where(filters)
    count_where, count_params = _where(filters, include_cursor=False)
    count_row = conn.execute(
        f"SELECT COUNT(*) AS count FROM alerts WHERE {count_where}", count_params
    ).fetchone()
    total = int(count_row["count"] if count_row else 0)

    rows = conn.execute(
        f"""
        SELECT id, source_name, source_url, source_host, group_name,
               category, severity, summary, iocs, timestamp,
               substr(COALESCE(description, ''), 1, 320) AS snippet
        FROM alerts
        WHERE {where}
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
        """,
        [*params, filters.limit + 1],
    ).fetchall()

    next_cursor = None
    if len(rows) > filters.limit:
        rows = rows[: filters.limit]
        last = rows[-1]
        next_cursor = (int(last["timestamp"]), int(last["id"]))

    return AlertPage(
        rows=[_row_dict(row) for row in rows],
        total=total,
        next_cursor=next_cursor,
    )


def list_new_alerts(
    conn: sqlite3.Connection,
    since: int,
    filters: Filters,
) -> list[dict[str, Any]]:
    where, params = _where(filters, include_cursor=False)
    rows = conn.execute(
        f"""
        SELECT id, source_name, source_url, source_host, group_name,
               category, severity, summary, iocs, timestamp,
               substr(COALESCE(description, ''), 1, 320) AS snippet
        FROM alerts
        WHERE {where} AND timestamp > ?
        ORDER BY timestamp ASC, id ASC
        LIMIT 100
        """,
        [*params, int(since)],
    ).fetchall()
    return [_row_dict(row) for row in rows]


def get_latest_timestamp(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(MAX(timestamp), 0) AS latest FROM alerts").fetchone()
    return int(row["latest"] if row else 0)


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id, source_name, source_url, source_host, group_name,
               content_hash, category, severity, summary, iocs, entities,
               timestamp, substr(COALESCE(description, ''), 1, 50000) AS snippet
        FROM alerts WHERE id = ?
        """,
        (alert_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_dict(row)


def get_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    today = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)
    week_ago = now - timedelta(days=7)
    day_ago = now - timedelta(hours=24)
    month_ago = now - timedelta(days=30)

    row = conn.execute(
        """
        SELECT COUNT(*) AS total,
               COALESCE(SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), 0) AS today,
               COALESCE(SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), 0) AS last_24h,
               COALESCE(SUM(CASE WHEN severity = 'high' AND timestamp >= ?
                                 THEN 1 ELSE 0 END), 0) AS high_7d,
               COALESCE(SUM(CASE WHEN source_host LIKE '%.onion'
                                 THEN 1 ELSE 0 END), 0) AS onion,
               COALESCE(SUM(CASE WHEN source_host NOT LIKE '%.onion'
                                 THEN 1 ELSE 0 END), 0) AS clearnet
        FROM alerts
        """,
        (
            int(today.timestamp()),
            int(day_ago.timestamp()),
            int(week_ago.timestamp()),
        ),
    ).fetchone()

    top_categories = [
        {"category": item["category"], "count": int(item["count"])}
        for item in conn.execute(
            """
            SELECT COALESCE(category, 'other') AS category, COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY COALESCE(category, 'other')
            ORDER BY count DESC
            LIMIT 6
            """,
            (int(month_ago.timestamp()),),
        ).fetchall()
    ]

    site_counts = {
        (item["status"] or "unknown"): int(item["count"])
        for item in conn.execute(
            "SELECT status, COUNT(*) AS count FROM sites GROUP BY status"
        ).fetchall()
    }

    return {
        "total": int(row["total"]),
        "today": int(row["today"]),
        "last_24h": int(row["last_24h"]),
        "high_7d": int(row["high_7d"]),
        "onion": int(row["onion"]),
        "clearnet": int(row["clearnet"]),
        "sites_up": site_counts.get("up", 0),
        "sites_down": site_counts.get("down", 0),
        "sites_unknown": site_counts.get("unknown", 0),
        "top_categories": top_categories,
    }


def get_sites(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT url, name, group_name, target_type, status, uptime_30,
               last_check, last_error, consecutive_failures
        FROM sites
        ORDER BY CASE status WHEN 'up' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                 name COLLATE NOCASE
        """
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["network"] = item.get("target_type") or network_label(
            host_from_url(item["url"])
        )
        result.append(item)
    return result


def get_filter_options(conn: sqlite3.Connection) -> dict[str, list[str]]:
    categories = [
        str(row["category"])
        for row in conn.execute(
            """
            SELECT DISTINCT COALESCE(category, 'other') AS category
            FROM alerts ORDER BY category LIMIT 100
            """
        ).fetchall()
    ]
    sources = [
        str(row["source_name"])
        for row in conn.execute(
            """
            SELECT DISTINCT source_name FROM alerts
            WHERE source_name IS NOT NULL AND source_name <> ''
            ORDER BY source_name LIMIT 200
            """
        ).fetchall()
    ]
    return {"categories": categories, "sources": sources}

import posixpath
import re
from typing import Optional
from urllib.parse import urlparse, urldefrag, urlunparse, parse_qsl, urlencode

from scraper.config import CONFIG

PAGE_IGNORE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
    ".exe", ".msi", ".dll", ".bin", ".apk", ".iso", ".img",
    ".sql", ".db", ".sqlite", ".bak", ".dump",
    ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf", ".ppt", ".pptx",
    ".txt", ".xml", ".json",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".mp4", ".avi", ".mkv", ".mov", ".webm",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
}

FORUM_NOISE_QUERY_PARAMS = {
    "sortby", "order", "sort", "direction", "desc", "asc",
    "datecut", "prefix", "prefix_id", "daysprune", "filter", "layout", "mode", "view",
    "pp", "perpage", "limit", "highlight", "synced",
    "s", "sid", "session", "session_id", "hash",
}

PAGE_BLOCKED_PATH_PREFIXES = (
    "/user", "/users", "/u/", "/member", "/members", "/memberlist",
    "/profile", "/profiles", "/account", "/conversation", "/conversations",
    "/messages", "/inbox", "/search", "/online", "/whos-online",
    "/latest-members", "/staff", "/moderators", "/login", "/logout",
    "/register", "/signup", "/password", "/attachment", "/attachments",
    "/tags", "/watched", "/find-new", "/misc", "/reputation",
    "/report", "/reports", "/help", "/faq", "/Forum-Introductions",
    "/Thread-Admin-DarkForums-Archive-Telegram-Channel",
    "/newreply.php", "/newthread.php", "/editpost.php", "/deletepost.php",
    "/private.php", "/sendmessage.php", "/printthread.php",
    "/syndication.php", "/calendar.php", "/showteam.php", "/stats.php",
    "/Forum-Support-Suggestions", "/Forum-The-Lounge", "/Forum-Freebies-Courses",
    "/Forum-Tutorials", "/Forum-Games", "/Forum-Doxes", "/Forum-HackTheBox-TryHackMe",
    "/Forum-Cracked-Accounts", "/Forum-Cracked-Tools", "/Forum-Services",
    "/Forum-Currency-Exchange", "/Forum-Scam-Reports", "/Forum-Buyers-Place",
    "/Forum-Source-Codes", "/bans", "/extras", "/newpoints",
    "/upgrades", "/awards", "/credits",
)

PAGE_BLOCKED_QUERY_SUBSTRINGS = (
    "profile", "uid=", "user=", "username=", "member=", "reputation",
    "nextnewest", "nextoldest", "pid=",
)

PAGE_CONTINUATION_RE = re.compile(
    r'(?:[?&]page=(\d+)(?:[&#]|$))'
    r'|(?:/page-(\d+)(?:/|$))'
    r'|(?:[-/]page-(\d+)(?:\.html)?(?:[/?#]|$))'
)


def is_onion_url(url: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower().endswith(".onion")
    except Exception:
        return False


def normalize_hostname(host: Optional[str]) -> str:
    if not host:
        return ""
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def redact_url(url: str) -> str:
    if not CONFIG.redact_urls_in_logs:
        return url
    try:
        return f"{urlparse(url).scheme}://[redacted]"
    except Exception:
        return "[redacted]"


def sanitize_url_for_storage(url: str) -> str:
    try:
        p = urlparse(str(url).strip())
        if not p.scheme or not p.hostname:
            return str(url).strip()
        netloc = p.hostname.lower()
        if p.port:
            netloc = f"{netloc}:{p.port}"
        return urlunparse((p.scheme.lower(), netloc, p.path or "/", p.params, p.query, ""))
    except Exception:
        return str(url).strip()


def normalize_page_url(url: str) -> str:
    try:
        url, _ = urldefrag(str(url).strip())
        p = urlparse(url)
        if not p.scheme or not p.hostname:
            return ""
        netloc = p.hostname.lower()
        if p.port:
            netloc = f"{netloc}:{p.port}"

        query = p.query
        if query:
            pairs = []
            for k, v in parse_qsl(query, keep_blank_values=True):
                lk = k.lower()
                lv = v.strip().lower()
                if lk in FORUM_NOISE_QUERY_PARAMS or lk.startswith("utm_"):
                    continue
                if lk == "page" and lv == "1":
                    continue
                if lk == "action" and lv in ("newpost", "lastpost", "linear", "threaded"):
                    continue
                pairs.append((k, v))

            pairs.sort(key=lambda x: x[0])
            query = urlencode(pairs)

        return f"{p.scheme.lower()}://{netloc}{p.path or '/'}{f'?{query}' if query else ''}"
    except Exception:
        return ""


def get_page_ext(url: str) -> str:
    try:
        return posixpath.splitext(urlparse(url).path.lower())[1]
    except Exception:
        return ""


def is_allowed_page_url(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        if not CONFIG.allow_clearnet_targets and not is_onion_url(url):
            return False
        if get_page_ext(url) in PAGE_IGNORE_EXTENSIONS:
            return False

        low = url.lower()
        if low.startswith(("javascript:", "mailto:", "data:")):
            return False

        if CONFIG.first_page_only:
            m = PAGE_CONTINUATION_RE.search(low)
            if m and int(m.group(1) or m.group(2) or m.group(3)) >= 2:
                return False

        path = (p.path or "/").lower()
        if path in ("/", "/index.html", "/index.htm", "/index.php"):
            return False

        if path.startswith(PAGE_BLOCKED_PATH_PREFIXES):
            return False

        q = (p.query or "").lower()
        if any(s in q for s in PAGE_BLOCKED_QUERY_SUBSTRINGS):
            return False

        return True
    except Exception:
        return False
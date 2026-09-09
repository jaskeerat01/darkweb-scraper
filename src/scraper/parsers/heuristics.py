import posixpath
from urllib.parse import urlparse
from scraper.parsers.url import PAGE_IGNORE_EXTENSIONS

PAGE_KEYWORDS = {
    "leak": 25, "leaks": 25, "victim": 20, "victims": 20,
    "company": 15, "companies": 15, "breach": 20, "data": 10,
    "publish": 20, "published": 20, "blog": 10, "news": 10,
    "post": 8, "posts": 8, "article": 8, "articles": 8,
    "archive": 10, "list": 8, "full": 6, "download": 4,
    "downloads": 4, "doc": 4, "docs": 4, "document": 5,
    "documents": 5, "database": 8, "dump": 8,
}

PAGE_NEGATIVE_KEYWORDS = {
    "login": -25, "signin": -25, "register": -25, "signup": -25,
    "forgot": -20, "password": -20, "contact": -10, "about": -5,
    "terms": -20, "privacy": -20, "policy": -20, "cart": -25,
    "checkout": -25, "wp-admin": -30, "wp-login": -30,
    "/css/": -20, "/js/": -20, "/assets/": -20, "/static/": -20,
    "/img/": -15, "/images/": -15, "javascript:": -100, "mailto:": -100,
}

ERROR_PAGE_HARD_MARKERS = (
    "err_timed_out", "err_connection_refused", "err_connection_reset",
    "err_connection_closed", "err_name_not_resolved", "err_proxy_connection_failed",
    "err_empty_response", "err_access_denied",
)

ERROR_PAGE_SOFT_MARKERS = (
    "this site can’t be reached", "this site can't be reached",
    "took too long to respond", "just a moment...", "checking your browser",
    "attention required", "one more step", "verify you are a human",
    "enable javascript and cookies", "ddos protection by", "checking if the site connection is secure",
)


def score_page_url(url: str, anchor_text: str = "") -> int:
    """Calculates relevance scores for frontier links based on path tokens and anchor text."""
    if not url:
        return -1000
    try:
        p = urlparse(url)
        path = p.path.lower()
        blob = f"{path} {p.query.lower()} {(anchor_text or '').lower()}"
        score = 0

        ext = posixpath.splitext(path)[1]
        if ext in (".html", ".htm", ".xhtml", ".shtml"):
            score += 30
        if path in ("/", "/index.html", "/index.htm"):
            score += 8
        if ext in PAGE_IGNORE_EXTENSIONS:
            score -= 250

        for kw, val in PAGE_KEYWORDS.items():
            if kw in blob:
                score += val
        for kw, val in PAGE_NEGATIVE_KEYWORDS.items():
            if kw in blob:
                score += val

        if len(p.query) > 120:
            score -= 5
        if len(path) > 180:
            score -= 5
        return score
    except Exception:
        return -1000


def looks_like_html(raw_html: str) -> bool:
    if not raw_html:
        return False
    sample = raw_html[:8000].lower()
    markers = ("<html", "<!doctype html", "<body", "<div", "<a ", "<table", "<p>", "<h1", "<h2", "<title")
    if any(m in sample for m in markers):
        return True
    return "<" in sample and ">" in sample


def looks_like_error_page(description: str) -> bool:
    content = (description or "").lower()
    if not content:
        return True
    if any(marker in content for marker in ERROR_PAGE_HARD_MARKERS):
        return True
    return sum(1 for marker in ERROR_PAGE_SOFT_MARKERS if marker in content) >= 2
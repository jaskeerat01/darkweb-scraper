import re
from typing import List, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from scraper.config import CONFIG
from scraper.parsers.url import normalize_hostname, normalize_page_url, is_allowed_page_url

_DOM_HASH_EXCLUDE = {"script", "style", "noscript", "iframe", "object", "embed", "svg", "head"}
_DOM_DESC_EXCLUDE = _DOM_HASH_EXCLUDE | {"nav", "header", "footer"}


def get_soup(raw_html: str) -> BeautifulSoup:
    """Builds a DOM tree with the fast C-based lxml parser, falling back to html.parser."""
    try:
        return BeautifulSoup(raw_html, "lxml")
    except Exception:
        return BeautifulSoup(raw_html, "html.parser")


def clean_text_for_hash(soup: BeautifulSoup) -> str:
    """Extracts non-volatile text, removing dynamic timestamps and view counters for deduplication."""
    chunks = []
    for s in soup.find_all(string=True):
        if s.parent and s.parent.name in _DOM_HASH_EXCLUDE:
            continue
        st = s.strip()
        if st:
            chunks.append(st)

    text = " ".join(chunks)
    text = re.sub(r'\b\d+\s*(?:minute|hour|day|week|month|year)s?\s+ago\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\b(?:views?|reads?|hits?|downloads?)\s*[:\-]?\s*[\d,]+\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\b[\d,]+\s*(?:views|reads|hits|downloads)\b', '', text, flags=re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()


def extract_first_post_element(soup: BeautifulSoup):
    try:
        container = soup.find(id="posts")
        if container is None:
            return None
        for div in container.find_all("div", class_=True):
            if "post" in (div.get("class") or []):
                body = div.find("div", class_=lambda c: c is not None and "post_body" in c)
                if body is not None:
                    return body
        return None
    except Exception:
        return None


def extract_post_description(soup: BeautifulSoup) -> str:
    """Extracts the initial thread publication body while ignoring navigation noise."""
    target = soup
    if CONFIG.first_post_only:
        first_post = extract_first_post_element(soup)
        if first_post is not None:
            target = first_post

    lines: List[str] = []
    blank = 0
    for element in target.find_all(string=True):
        if element.parent and element.parent.name in _DOM_DESC_EXCLUDE:
            continue
        chunk = element.strip()
        if not chunk:
            blank += 1
            if blank <= 1:
                lines.append("")
        else:
            blank = 0
            lines.append(chunk)

    return "\n".join(lines).strip()


def extract_page_links(soup: BeautifulSoup, base_url: str, same_host_only: bool = True) -> List[Tuple[str, str]]:
    """Gathers qualified hyperlinks and meta refresh directives from the document."""
    links: List[Tuple[str, str]] = []
    try:
        base_host = normalize_hostname(urlparse(base_url).hostname)
        for tag in soup.find_all(["a", "frame", "iframe"]):
            href = (tag.get("href") or tag.get("src") or "").strip()
            if not href or href.lower().startswith(("javascript:", "mailto:", "#", "data:")):
                continue

            absolute = normalize_page_url(urljoin(base_url, href))
            if not absolute:
                continue

            p = urlparse(absolute)
            if p.scheme not in ("http", "https"):
                continue
            if same_host_only and normalize_hostname(p.hostname) != base_host:
                continue
            if not is_allowed_page_url(absolute):
                continue

            text = tag.get_text(" ", strip=True)[:300] if tag.name == "a" else ""
            links.append((absolute, text))

        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if meta.get("http-equiv", "").lower() != "refresh":
                continue
            content = meta.get("content", "")
            low = content.lower()
            if "url=" not in low:
                continue

            target = content[low.index("url=") + 4:].strip().strip(";").strip().strip("\"'").strip()
            absolute = normalize_page_url(urljoin(base_url, target))
            if not absolute:
                continue

            p = urlparse(absolute)
            if p.scheme not in ("http", "https"):
                continue
            if same_host_only and normalize_hostname(p.hostname) != base_host:
                continue
            if is_allowed_page_url(absolute):
                links.append((absolute, ""))
    except Exception:
        pass
    return links
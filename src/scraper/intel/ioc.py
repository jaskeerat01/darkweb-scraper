import re
from typing import List

from bs4 import BeautifulSoup

IOC_PATTERN_STRINGS = (
    r'\b(?:t\.me|telegram\.me)/(?:joinchat/)?([A-Za-z0-9_]{5,32})\b',
    r'(?<![\w@.])@[ \t]?([A-Za-z][A-Za-z0-9_]{4,31})\b',
    r'\b05[0-9a-fA-F]{64}\b',
    r'\b[A-Fa-f0-9]{76}\b',
    r'(?:TOX|WALLET|BTC|ETH|XMR|LTC|BCH|ADDRESS|PGP)\s*[:\-]?\s*([A-Za-z0-9]{30,})',
    r'\b[A-Z0-9]{56,}\b',
    r'\bbc1[a-z0-9]{20,60}\b',
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    r'\bltc1[a-z0-9]{20,60}\b',
    r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',
    r'\b0x[a-fA-F0-9]{40}\b',
    r'\b[48][0-9A-B][1-9A-HJ-NP-Za-km-z]{93}\b',
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    r'\b[a-z2-7]{16,64}\.onion\b',
)

IOC_PATTERNS = tuple(re.compile(pattern) for pattern in IOC_PATTERN_STRINGS)

MAX_IOCS = 250
MAX_IOC_LENGTH = 512
MAX_IOC_SCAN_CHARS = 512 * 1024

CONTACT_LINK_RE = re.compile(
    r'(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})'
    r'|mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})'
    r'|\b(05[0-9a-fA-F]{64})\b'
    r'|\b([A-Fa-f0-9]{76})\b'
    r'|keybase\.io/([A-Za-z0-9_.-]{2,50})',
    re.IGNORECASE,
)


def extract_iocs(text: str) -> List[str]:
    """Identify crypto wallets, handles, hashes, emails, and onion addresses."""
    found: dict[str, None] = {}
    haystack = (text or "")[:MAX_IOC_SCAN_CHARS]
    for pattern in IOC_PATTERNS:
        for match in pattern.finditer(haystack):
            value = (match.group(1) if match.groups() else match.group(0)).strip()
            if not (5 <= len(value) <= MAX_IOC_LENGTH):
                continue
            found.setdefault(value, None)
            if len(found) >= MAX_IOCS:
                return list(found)
    return list(found)


def extract_contact_links(soup: BeautifulSoup) -> List[str]:
    """Extract contact handles directly from anchor href attributes."""
    found: dict[str, None] = {}
    try:
        for tag in soup.find_all("a", href=True, limit=5000):
            match = CONTACT_LINK_RE.search(tag.get("href") or "")
            if not match:
                continue
            value = next((group for group in match.groups() if group), "").strip()
            if 5 <= len(value) <= MAX_IOC_LENGTH:
                found.setdefault(value, None)
                if len(found) >= MAX_IOCS:
                    break
    except Exception:
        pass
    return list(found)

import re
from typing import List
from bs4 import BeautifulSoup

IOC_PATTERNS = [
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
]

CONTACT_LINK_RE = re.compile(
    r'(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})'
    r'|mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})'
    r'|\b(05[0-9a-fA-F]{64})\b'
    r'|\b([A-Fa-f0-9]{76})\b'
    r'|keybase\.io/([A-Za-z0-9_.-]{2,50})',
    re.IGNORECASE,
)


def extract_iocs(text: str) -> List[str]:
    """Identifies crypto wallets, communication handles, hashes, and email artifacts."""
    iocs: List[str] = []
    for pattern in IOC_PATTERNS:
        for m in re.finditer(pattern, text):
            val = (m.group(1) if m.groups() else m.group(0)).strip()
            if len(val) >= 5 and val not in iocs:
                iocs.append(val)
    return iocs


def extract_contact_links(soup: BeautifulSoup) -> List[str]:
    """Extracts contact handles directly from anchor href attributes."""
    out: List[str] = []
    try:
        for tag in soup.find_all("a", href=True):
            m = CONTACT_LINK_RE.search(tag.get("href") or "")
            if m:
                val = next((g for g in m.groups() if g), "").strip()
                if len(val) >= 5 and val not in out:
                    out.append(val)
    except Exception:
        pass
    return out
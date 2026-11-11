"""Deterministic category and severity classification.

The local LLM produces a summary and a relevance verdict.  Historically it
always returned ``other`` for the category, so the dashboard had nothing useful
to group on.  These transparent keyword rules fill that gap.  They are a
heuristic priority, not a model verdict.
"""

from __future__ import annotations

import re
from typing import Iterable, Literal

Severity = Literal["high", "medium", "low"]

_CATEGORY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ransomware",
        re.compile(
            r"\b(?:ransomware|ransom|extortion|lockbit|blackcat|alphv|cl0p|"
            r"akira|play\s+ransomware|encryptor)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "credentials",
        re.compile(
            r"\b(?:credentials?|combo\s*list|logins?|cookies?|stealer|"
            r"infostealer|passwords?|session\s+tokens?|access\s+tokens?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "data_leak",
        re.compile(
            r"\b(?:data\s+leak|leaked|leak|breach|breached|database|dump|"
            r"exfiltrat\w*|stolen\s+data|records?|customers?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "exploit",
        re.compile(
            r"\b(?:0day|zero[- ]day|exploit|rce|remote\s+code|vulnerabilit\w*|"
            r"cve-\d{4}-\d+|privilege\s+escalation)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "malware",
        re.compile(
            r"\b(?:malware|trojan|rat\b|botnet|loader|backdoor|rootkit|"
            r"keylogger|worm\b)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "marketplace",
        re.compile(
            r"\b(?:for\s+sale|vendor|escrow|price|marketplace|market\b|"
            r"shop\b|listing)\b",
            re.IGNORECASE,
        ),
    ),
)

_KNOWN_CATEGORIES = {
    "ransomware",
    "credentials",
    "data_leak",
    "exploit",
    "malware",
    "marketplace",
    "other",
}

_SEVERITY_BY_CATEGORY: dict[str, Severity] = {
    "ransomware": "high",
    "credentials": "high",
    "data_leak": "high",
    "exploit": "medium",
    "malware": "medium",
    "marketplace": "low",
    "other": "low",
}

_ESCALATORS = re.compile(
    r"\b(?:victims?|customers?|employees?|millions?|database|dump|"
    r"plaintext|credit\s+cards?|ssn|passports?|medical|source\s+code)\b",
    re.IGNORECASE,
)


def normalize_category(value: str | None) -> str:
    candidate = (value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return candidate if candidate in _KNOWN_CATEGORIES else "other"


def derive_category(text: str, llm_category: str | None = "other") -> str:
    """Return a stable category, preserving a meaningful LLM result."""
    provided = normalize_category(llm_category)
    if provided != "other":
        return provided
    haystack = text or ""
    for category, pattern in _CATEGORY_PATTERNS:
        if pattern.search(haystack):
            return category
    return "other"


def derive_severity(category: str, text: str = "") -> Severity:
    """Map a category to a severity, escalating high-signal leaks."""
    normalized = normalize_category(category)
    severity = _SEVERITY_BY_CATEGORY.get(normalized, "low")
    if normalized in {"data_leak", "exploit", "malware"} and _ESCALATORS.search(text or ""):
        if severity == "medium":
            return "high"
    return severity


def category_options() -> Iterable[str]:
    return tuple(_KNOWN_CATEGORIES)

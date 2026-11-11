from scraper.intel.taxonomy import derive_category, derive_severity, normalize_category


def test_category_detection():
    assert derive_category("LockBit ransomware claims a new victim") == "ransomware"
    assert derive_category("A database dump with customer records") == "data_leak"
    assert derive_category("Combo list of passwords and cookies") == "credentials"
    assert derive_category("New 0day RCE exploit with CVE-2026-1234") == "exploit"
    assert derive_category("A trojan loader and botnet panel") == "malware"
    assert derive_category("Vendor offers escrow for a listing") == "marketplace"
    assert derive_category("hello world") == "other"


def test_llm_category_is_preserved_when_meaningful():
    assert derive_category("hello", "ransomware") == "ransomware"
    assert derive_category("hello", "other") == "other"


def test_severity_mapping_and_escalation():
    assert derive_severity("ransomware") == "high"
    assert derive_severity("exploit") == "medium"
    assert derive_severity("exploit", "millions of customer records") == "high"
    assert derive_severity("other") == "low"


def test_normalize_category():
    assert normalize_category("Data-Leak") == "data_leak"
    assert normalize_category("unknown") == "other"

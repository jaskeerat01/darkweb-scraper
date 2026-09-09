from scraper.intel.ioc import extract_iocs


def test_extract_iocs():
    sample_text = """
    Send ransom of 5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.
    Or ETH to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.
    Monero: 44AFFq5AxYBfmGWRJQP44R9Z4L4vc7wzP4um92tdZKeuvvBog2L9ENcrYYJFBTVMe4STR1RnnCrZXwaJh5TXRev41AseGyQ
    Reach admin on Telegram: https://t.me/threat_actor_test
    Email: leak_support@protonmail.com
    Mirrors: testonionaddress234567.onion
    """
    iocs = extract_iocs(sample_text)

    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in iocs
    assert "0x71C7656EC7ab88b098defB751B7401B5f6d8976F" in iocs
    assert "threat_actor_test" in iocs
    assert "leak_support@protonmail.com" in iocs
    assert any("44AFFq5AxYBfmGW" in ioc for ioc in iocs)
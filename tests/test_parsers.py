from scraper.parsers.dom import get_soup, extract_post_description, clean_text_for_hash


def test_extract_post_description(sample_forum_html):
    soup = get_soup(sample_forum_html)
    description = extract_post_description(soup)
    assert "Massive database leaked for company Acme Corp" in description
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in description


def test_clean_text_for_hash_removes_relative_time():
    raw_html = """
    <div>
        <h2>Breach Dump</h2>
        <span>Posted 10 minutes ago</span>
        <span>Views: 1,420</span>
        <p>Actual content payload</p>
    </div>
    """
    soup = get_soup(raw_html)
    cleaned = clean_text_for_hash(soup)
    assert "10 minutes ago" not in cleaned
    assert "1,420" not in cleaned
    assert "Breach Dump" in cleaned
    assert "Actual content payload" in cleaned
import sys
from pathlib import Path

import pytest

# Ensure src/ is importable during pytest runs
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scraper.config import Config
from scraper.storage.db import init_db


@pytest.fixture
def sample_forum_html():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Breach Forums - Thread View</title></head>
    <body>
        <div id="posts">
            <div class="post">
                <div class="post_body">
                    Massive database leaked for company Acme Corp.
                    Includes 50,000 customers with plaintext passwords.
                    Contact us at telegram: https://t.me/dark_intel_actor
                    Or send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.
                    Secondary contact: operator@leakservice.onion.
                </div>
            </div>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def temp_config(tmp_path):
    return Config(
        db_path=str(tmp_path / "alerts.db"),
        csv_path=str(tmp_path / "forum_sites.csv"),
        llm_cache_enabled=False,
        llm_fail_open=False,
        data_retention_days=30,
        llm_cache_days=7,
    )


@pytest.fixture
def temp_db(temp_config):
    init_db(config=temp_config)
    return Path(temp_config.db_path)

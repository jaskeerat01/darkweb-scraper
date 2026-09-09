import sys
from pathlib import Path
import pytest

# Ensure src/ is importable during pytest runs
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


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
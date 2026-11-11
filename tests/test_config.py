import pytest

from scraper.config import Config
from scraper.core.exceptions import ConfigError


def test_defaults_match_documented_values():
    config = Config()
    assert config.max_pages_per_site == 50
    assert config.max_parallel_sites == 3
    assert config.max_parallel_fetches == 3
    assert config.allow_clearnet_targets is False
    assert config.clearnet_enabled is False


def test_from_env_parses_bools_lists_and_ports():
    config = Config.from_env(
        {
            "KEYWORDS": " alpha, beta ,, gamma ",
            "LLM_PREFILTER_KEYWORDS": "yes",
            "CLEARNET_ALLOWED_PORTS": "80, 8443",
            "ALLOW_CLEARNET_TARGETS": "true",
            "CLEARNET_ALLOWED_DOMAINS": "example.com, news.example.org",
        },
        load_dotenv_file=False,
    )
    assert config.keywords == ("alpha", "beta", "gamma")
    assert config.llm_prefilter_keywords is True
    assert config.clearnet_allowed_ports == frozenset({80, 8443})
    assert config.clearnet_enabled is True


@pytest.mark.parametrize(
    "env",
    [
        {"MAX_PARALLEL_SITES": "0"},
        {"MAX_PARALLEL_SITES": "abc"},
        {"MAX_PAGES_PER_SITE": "-1"},
        {"TOR_SOCKS_PORT": "70000"},
        {"CLEARNET_ALLOWED_PORTS": "99,abc"},
        {"LLM_TEMPERATURE": "5"},
    ],
)
def test_invalid_values_raise_config_error(env):
    with pytest.raises(ConfigError):
        Config.from_env(env, load_dotenv_file=False)


def test_clearnet_requires_explicit_scope():
    enabled_no_scope = Config.from_env(
        {"ALLOW_CLEARNET_TARGETS": "true"}, load_dotenv_file=False
    )
    assert enabled_no_scope.clearnet_enabled is False

    enabled_any = Config.from_env(
        {"ALLOW_CLEARNET_TARGETS": "true", "CLEARNET_ALLOW_ANY": "true"},
        load_dotenv_file=False,
    )
    assert enabled_any.clearnet_enabled is True

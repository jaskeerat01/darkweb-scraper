"""Read-only FastAPI dashboard for the Dark Web Threat Intelligence Engine."""

from scraper.dashboard.app import create_app
from scraper.dashboard.settings import DashboardConfigError, DashboardSettings

__all__ = ["create_app", "DashboardConfigError", "DashboardSettings"]

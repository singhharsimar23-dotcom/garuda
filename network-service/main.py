"""
UTNE Service Main Entrypoint
Exports FastAPI app for Render container deployment.
"""

from api import app

__all__ = ["app"]

"""Vercel Serverless Function entry point for GARUDA API."""
import sys
import os

# Add root project directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from garuda.api.main import app, handler

# Export app for Vercel Python runtime
__all__ = ["app", "handler"]

"""
Alias wrapper for GARUDA IOC confidence scoring engine.
Exposes compute_ioc_confidence per spec requirement.
"""

from garuda.detection.ioc_confidence import compute_ioc_confidence

__all__ = ["compute_ioc_confidence"]

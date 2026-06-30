"""Centralised logging setup."""
from __future__ import annotations

import logging
import os

_CONFIGURED = False


def get_logger(name: str = "adf") -> logging.Logger:
    """Return a configured logger. Level controlled by the ADF_LOG_LEVEL env var."""
    global _CONFIGURED
    if not _CONFIGURED:
        level = os.environ.get("ADF_LOG_LEVEL", "INFO").upper()
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        root = logging.getLogger("adf")
        root.setLevel(getattr(logging, level, logging.INFO))
        root.addHandler(handler)
        root.propagate = False
        _CONFIGURED = True
    return logging.getLogger(name if name.startswith("adf") else f"adf.{name}")

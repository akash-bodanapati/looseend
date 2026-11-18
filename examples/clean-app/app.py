"""Small, clean sample module."""
from __future__ import annotations

import json
import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def load_settings(path: Path) -> dict:
    """Read a JSON settings file, returning an empty dict if it is missing."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        LOGGER.info("no settings file at %s", path)
        return {}


def total(values: list[float]) -> float:
    """Return the sum of the values."""
    return sum(values)

"""Example clean Python file."""
import ast
import hashlib
import logging

logger = logging.getLogger(__name__)


def safe_eval(expression: str) -> object:
    """Safely evaluate a mathematical expression."""
    return ast.literal_eval(expression)


def hash_data(data: bytes) -> str:
    """Hash data with SHA-256."""
    return hashlib.sha256(data).hexdigest()


def process(items: list[str]) -> list[str]:
    """Process a list of items."""
    return [item.strip() for item in items if item]

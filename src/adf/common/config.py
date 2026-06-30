"""Configuration loading: YAML config + environment variables."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_CONFIG = _PACKAGE_ROOT / "configs" / "default.yaml"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (avoids an extra dependency). Does not overwrite real env vars."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


class Config:
    """Read-only view over the merged YAML configuration with dotted-key access."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def __getitem__(self, key: str) -> Any:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    @property
    def raw(self) -> dict[str, Any]:
        return self._data


@lru_cache(maxsize=8)
def load_config(path: str | None = None) -> Config:
    """Load YAML config and the .env file once (cached per path)."""
    _load_dotenv(_PACKAGE_ROOT / ".env")
    cfg_path = Path(path) if path else _DEFAULT_CONFIG
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Config file not found: {cfg_path}")
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    return Config(data)


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)

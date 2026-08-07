"""Hostfold: safe, per-host materialized SSH views."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("hostfold")
except PackageNotFoundError:  # pragma: no cover - source-tree fallback
    __version__ = "0.3.0"

__all__ = ["__version__"]

"""Minimal compatibility shim for the removed stdlib `imp` module.

This shim provides just enough functionality for legacy `nose` usage
that imports `imp` and calls `find_module` / `load_module` and lock
helpers. It's intentionally small and uses importlib under the hood.

Note: This is a focused compatibility workaround for running tests
in a Python 3.13 environment where `imp` was removed. Prefer removing
the `nose` dependency or running tests on Python <=3.12 in CI.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from types import ModuleType
from typing import Optional, Tuple, Any


def find_module(name: str, path: Optional[Any] = None) -> Tuple[Optional[Any], Optional[str], Optional[Any]]:
    """Find a module spec for `name` and return (file, pathname, description).

    This mirrors the old `imp.find_module` minimal contract expected by
    legacy code: callers typically pass the returned pathname to
    `load_module`. We return a tuple where `pathname` is the origin path
    from importlib's spec.
    """
    spec = importlib.util.find_spec(name)
    if spec is None:
        raise ImportError(name)
    return (None, spec.origin, None)


def load_module(name: str, file: Optional[Any], pathname: Optional[str], description: Optional[Any]) -> ModuleType:
    """Load and return the module named `name` using importlib.

    This mimics `imp.load_module` by delegating to `importlib.import_module`.
    """
    # If module already loaded, return it
    if name in sys.modules:
        return sys.modules[name]
    module = importlib.import_module(name)
    return module


def acquire_lock():
    """No-op lock for compatibility with legacy callers."""


def release_lock():
    """No-op unlock for compatibility with legacy callers."""

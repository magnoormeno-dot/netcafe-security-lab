"""Platform helpers used to keep Windows-specific behavior optional."""

from __future__ import annotations

import os
import platform
from pathlib import Path


def is_windows() -> bool:
    """Return whether the current platform is Windows."""

    return platform.system().lower() == "windows"


def is_linux() -> bool:
    """Return whether the current platform is Linux."""

    return platform.system().lower() == "linux"


def normalize_path(path: str | Path) -> str:
    """Return a normalized absolute path string without resolving missing paths."""

    return str(Path(path).expanduser().absolute())


def is_probably_writable_location(path: str | Path) -> bool:
    """Return whether a path is in a user-writable or temporary location."""

    value = str(path).lower().replace("/", "\\")
    markers = [
        "\\users\\",
        "\\appdata\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\temp\\",
        "\\tmp\\",
        "\\programdata\\",
        "\\windows\\temp\\",
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
    ]
    return any(marker in value for marker in markers)


def env_path(name: str, default: str) -> Path:
    """Return an environment-derived path with a fallback."""

    return Path(os.environ.get(name, default)).expanduser()

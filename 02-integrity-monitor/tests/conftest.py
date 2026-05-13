from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    root = tmp_path / "billing"
    root.mkdir()
    (root / "agent.exe").write_bytes(b"agent-v1")
    (root / "config.json").write_text('{"server": "billing"}', encoding="utf-8")
    cache = root / "cache"
    cache.mkdir()
    (cache / "runtime.tmp").write_text("ignore", encoding="utf-8")
    return root


@pytest.fixture()
def hmac_key() -> bytes:
    return b"unit-test-hmac-key-32-bytes-long"


@pytest.fixture()
def fixture_dir() -> Path:
    return Path(__file__).parent / "fixtures"

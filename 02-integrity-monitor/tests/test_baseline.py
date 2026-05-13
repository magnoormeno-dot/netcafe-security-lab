from __future__ import annotations

import json
from pathlib import Path

import pytest

from integrity_monitor.core.baseline import (
    BaselineIntegrityError,
    BaselineManager,
    BaselineVersion,
    FileRecord,
)


def record(path: str, digest: str = "abc") -> FileRecord:
    return FileRecord(path=path, size=3, mtime_ns=1, hashes={"sha256": digest})


def test_json_baseline_create_and_latest(tmp_path: Path, hmac_key: bytes) -> None:
    manager = BaselineManager(tmp_path / "baseline.json", hmac_key=hmac_key)
    version = manager.create_version([record("a.txt")], metadata={"host": "client-01"})

    latest = manager.latest_version()

    assert latest.version_id == version.version_id
    assert latest.metadata["host"] == "client-01"
    assert manager.verify_version(latest)


def test_sqlite_baseline_create_and_list(tmp_path: Path, hmac_key: bytes) -> None:
    manager = BaselineManager(tmp_path / "baseline.sqlite", hmac_key=hmac_key)
    manager.create_version([record("a.txt")])
    manager.create_version([record("b.txt")])

    versions = manager.list_versions()

    assert len(versions) == 2
    assert all(manager.verify_version(version) for version in versions)


def test_baseline_tamper_detection(tmp_path: Path, hmac_key: bytes) -> None:
    path = tmp_path / "baseline.json"
    manager = BaselineManager(path, hmac_key=hmac_key)
    manager.create_version([record("a.txt")])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["versions"][0]["records"]["a.txt"]["hashes"]["sha256"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BaselineIntegrityError):
        manager.latest_version()


def test_baseline_diff_records(tmp_path: Path) -> None:
    manager = BaselineManager(tmp_path / "baseline.json")
    baseline = BaselineVersion.create(
        [record("same.txt"), record("gone.txt"), record("changed.txt", "old")]
    )
    current = [record("same.txt"), record("changed.txt", "new"), record("added.txt")]

    diff = manager.diff_records(baseline, current)

    assert [item.path for item in diff.added] == ["added.txt"]
    assert [item.path for item in diff.removed] == ["gone.txt"]
    assert diff.modified[0][0].path == "changed.txt"
    assert diff.has_changes()


def test_baseline_rollback_creates_new_version(tmp_path: Path, hmac_key: bytes) -> None:
    manager = BaselineManager(tmp_path / "baseline.json", hmac_key=hmac_key)
    first = manager.create_version([record("a.txt")])
    manager.create_version([record("b.txt")])

    rolled_back = manager.rollback(first.version_id)

    assert rolled_back.version_id != first.version_id
    assert "a.txt" in rolled_back.records
    assert rolled_back.metadata["rolled_back_from"] == first.version_id

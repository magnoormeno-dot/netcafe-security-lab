from __future__ import annotations

from pathlib import Path

from integrity_monitor.core.baseline import BaselineManager
from integrity_monitor.core.file_integrity import FileIntegrityMonitor, ScanTarget


def test_scan_records_files(sample_tree: Path) -> None:
    monitor = FileIntegrityMonitor([sample_tree], algorithms=["sha256"], excludes=["*.tmp"])

    result = monitor.scan()

    names = {Path(record.path).name for record in result.records}
    assert names == {"agent.exe", "config.json"}
    assert all("sha256" in record.hashes for record in result.records)


def test_create_baseline_and_detect_no_changes(
    sample_tree: Path, tmp_path: Path, hmac_key: bytes
) -> None:
    manager = BaselineManager(tmp_path / "baseline.json", hmac_key=hmac_key)
    monitor = FileIntegrityMonitor([sample_tree], algorithms=["sha256"], baseline_manager=manager)
    monitor.create_baseline()

    result = monitor.scan()

    assert result.diff is not None
    assert not result.diff.has_changes()


def test_detect_modified_file(sample_tree: Path, tmp_path: Path) -> None:
    manager = BaselineManager(tmp_path / "baseline.json")
    monitor = FileIntegrityMonitor([sample_tree], baseline_manager=manager)
    monitor.create_baseline()
    (sample_tree / "agent.exe").write_bytes(b"agent-v2")

    result = monitor.scan()

    assert [change.change_type for change in result.changes] == ["modified"]


def test_detect_added_and_removed_files(sample_tree: Path, tmp_path: Path) -> None:
    manager = BaselineManager(tmp_path / "baseline.json")
    monitor = FileIntegrityMonitor([sample_tree], baseline_manager=manager)
    monitor.create_baseline()
    (sample_tree / "config.json").unlink()
    (sample_tree / "new.dll").write_bytes(b"dll")

    result = monitor.scan()

    assert {change.change_type for change in result.changes} == {"added", "removed"}


def test_glob_target(sample_tree: Path) -> None:
    monitor = FileIntegrityMonitor([ScanTarget(str(sample_tree / "*.exe"))])

    result = monitor.scan()

    assert len(result.records) == 1
    assert result.records[0].path.endswith("agent.exe")


def test_incremental_cache_reuses_hash(sample_tree: Path) -> None:
    monitor = FileIntegrityMonitor([sample_tree])
    first = monitor.record_file(sample_tree / "agent.exe")
    second = monitor.record_file(sample_tree / "agent.exe")

    assert first.hashes == second.hashes
    assert len(monitor._cache) == 1


def test_heuristic_finding_for_writable_executable(tmp_path: Path) -> None:
    downloads = tmp_path / "Users" / "player" / "Downloads"
    downloads.mkdir(parents=True)
    tool = downloads / "tool.exe"
    tool.write_bytes(b"tool")
    monitor = FileIntegrityMonitor([tool])

    result = monitor.scan()

    assert any(
        finding.rule_id == "heuristic.writable_executable_path" for finding in result.findings
    )

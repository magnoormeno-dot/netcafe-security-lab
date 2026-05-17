from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from integrity_monitor.cli import main


def test_cli_baseline_create_and_scan(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"

    create = runner.invoke(
        main,
        ["baseline", "create", "--path", str(sample_tree), "--store", str(store)],
    )
    scan = runner.invoke(main, ["scan", "--path", str(sample_tree), "--store", str(store)])

    assert create.exit_code == 0
    assert scan.exit_code == 0
    assert '"changes": 0' in scan.output


def test_cli_uses_configured_targets_without_path(sample_tree: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "baseline.json"
    config = tmp_path / "monitor.yaml"
    config.write_text(
        f'targets:\n  - "{sample_tree.as_posix()}"\nalgorithms:\n  - sha256\n',
        encoding="utf-8",
    )

    create = runner.invoke(
        main,
        ["baseline", "create", "--config", str(config), "--store", str(store)],
    )
    scan = runner.invoke(
        main,
        ["scan", "--config", str(config), "--store", str(store)],
    )

    assert create.exit_code == 0
    assert scan.exit_code == 0
    assert '"changes": 0' in scan.output


def test_cli_verify_detects_missing_store(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["verify", "--store", str(tmp_path / "missing.json")])

    assert result.exit_code == 0
    assert "All baseline versions verified" in result.output

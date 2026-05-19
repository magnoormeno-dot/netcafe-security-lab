from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import cast

import pytest

from integrity_monitor.core import process_monitor as process_monitor_module
from integrity_monitor.core.process_monitor import (
    ProcessMonitor,
    ProcessObservation,
    PsutilProcessProvider,
    WindowsSignatureVerifier,
)


class FakeProvider:
    def __init__(self, observations: list[ProcessObservation]) -> None:
        self._observations = observations

    def observations(self) -> list[ProcessObservation]:
        return self._observations


def obs(
    pid: int,
    name: str,
    exe: str | None,
    *,
    ppid: int | None = None,
    sha256: str | None = None,
) -> ProcessObservation:
    return ProcessObservation(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        username="user",
        cmdline=[name],
        cwd=None,
        create_time=1.0,
        sha256=sha256,
    )


class FakePsutilProcess:
    def __init__(
        self,
        info: dict[str, object],
        *,
        parent_name: str | None = None,
        parent_exe: str | None = None,
    ) -> None:
        self.info = info
        self.pid = cast(int, info["pid"])
        self._parent_name = parent_name
        self._parent_exe = parent_exe

    def name(self) -> str | None:
        return self._parent_name

    def exe(self) -> str | None:
        return self._parent_exe


def test_detect_writable_process_path() -> None:
    monitor = ProcessMonitor(
        provider=FakeProvider([obs(1, "tool.exe", "C:\\Users\\player\\Downloads\\tool.exe")]),
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    assert any(finding.rule_id == "process.writable_path_execution" for finding in findings)


def test_detect_hash_baseline_drift() -> None:
    path = "C:\\Program Files\\CafeBilling\\agent.exe"
    monitor = ProcessMonitor(
        provider=FakeProvider([obs(1, "agent.exe", path, sha256="bad")]),
        expected_hashes={path: "good"},
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    assert any(finding.rule_id == "process.hash_baseline_drift" for finding in findings)


def test_detect_suspicious_child_process() -> None:
    parent = obs(10, "billing-agent.exe", "C:\\CafeBilling\\billing-agent.exe")
    child = obs(
        11,
        "powershell.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ppid=10,
    )
    monitor = ProcessMonitor(provider=FakeProvider([parent, child]), include_unsigned_check=False)

    findings = monitor.scan()

    assert any(
        finding.rule_id == "process.suspicious_child_of_protected_process" for finding in findings
    )


def test_missing_executable_path_is_reported() -> None:
    monitor = ProcessMonitor(
        provider=FakeProvider([obs(1, "billing-agent.exe", "C:\\CafeBilling\\missing.exe")]),
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    assert any(finding.rule_id == "process.missing_executable_path" for finding in findings)


def test_allowed_writable_process_suppresses_finding() -> None:
    monitor = ProcessMonitor(
        provider=FakeProvider(
            [obs(1, "approved.exe", "C:\\Users\\player\\Downloads\\approved.exe")]
        ),
        allowed_writable_processes={"approved.exe"},
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    assert not any(finding.rule_id == "process.writable_path_execution" for finding in findings)


def test_hash_baseline_match_is_not_reported() -> None:
    path = "C:\\Program Files\\CafeBilling\\agent.exe"
    monitor = ProcessMonitor(
        provider=FakeProvider([obs(1, "agent.exe", path, sha256="good")]),
        expected_hashes={path: "good"},
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    assert not any(finding.rule_id == "process.hash_baseline_drift" for finding in findings)


def test_parent_child_detection_uses_parent_name_fallback() -> None:
    child = ProcessObservation(
        pid=11,
        ppid=10,
        name="reg.exe",
        exe="C:\\Windows\\System32\\reg.exe",
        username="user",
        cmdline=["reg.exe", "add"],
        cwd=None,
        create_time=1.0,
        parent_name="restore-watchdog.exe",
        parent_exe="C:\\Cafe\\restore-watchdog.exe",
    )
    monitor = ProcessMonitor(provider=FakeProvider([child]), include_unsigned_check=False)

    findings = monitor.scan()

    assert any(
        finding.rule_id == "process.suspicious_child_of_protected_process" for finding in findings
    )


def test_unsigned_sensitive_process_is_reported_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_monitor_module, "is_windows", lambda: True)
    monkeypatch.setattr("integrity_monitor.core.process_monitor.os.path.exists", lambda _path: True)
    observation = ProcessObservation(
        pid=10,
        ppid=None,
        name="billing-agent.exe",
        exe="C:\\Program Files\\CafeBilling\\billing-agent.exe",
        username="cashier",
        cmdline=["billing-agent.exe"],
        cwd=None,
        create_time=1.0,
        signature_status="NotSigned",
    )
    monitor = ProcessMonitor(provider=FakeProvider([observation]), include_unsigned_check=True)

    findings = monitor.scan()

    assert any(finding.rule_id == "process.unsigned_sensitive_process" for finding in findings)


def test_valid_signature_is_not_reported_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_monitor_module, "is_windows", lambda: True)
    monkeypatch.setattr("integrity_monitor.core.process_monitor.os.path.exists", lambda _path: True)
    observation = ProcessObservation(
        pid=10,
        ppid=None,
        name="billing-agent.exe",
        exe="C:\\Program Files\\CafeBilling\\billing-agent.exe",
        username="cashier",
        cmdline=["billing-agent.exe"],
        cwd=None,
        create_time=1.0,
        signature_status="Valid",
    )
    monitor = ProcessMonitor(provider=FakeProvider([observation]), include_unsigned_check=True)

    findings = monitor.scan()

    assert not any(finding.rule_id == "process.unsigned_sensitive_process" for finding in findings)


def test_missing_sensitive_executable_uses_medium_severity() -> None:
    monitor = ProcessMonitor(
        provider=FakeProvider(
            [obs(1, "billing-agent.exe", "C:\\CafeBilling\\missing-sensitive.exe")]
        ),
        include_unsigned_check=False,
    )

    findings = monitor.scan()

    finding = next(
        finding for finding in findings if finding.rule_id == "process.missing_executable_path"
    )
    assert finding.severity == "medium"


def test_psutil_provider_builds_observations_and_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exe = tmp_path / "agent.exe"
    exe.write_bytes(b"agent")
    expected_hash = hashlib.sha256(b"agent").hexdigest()
    parent = FakePsutilProcess(
        {
            "pid": 10,
            "ppid": None,
            "name": "services.exe",
            "exe": "C:\\Windows\\System32\\services.exe",
            "username": "SYSTEM",
            "cmdline": ["services.exe"],
            "cwd": None,
            "create_time": 100.0,
        },
        parent_name="services.exe",
        parent_exe="C:\\Windows\\System32\\services.exe",
    )
    child = FakePsutilProcess(
        {
            "pid": 11,
            "ppid": "10",
            "name": "agent.exe",
            "exe": str(exe),
            "username": "cashier",
            "cmdline": ["agent.exe", "--monitor"],
            "cwd": str(tmp_path),
            "create_time": "123.5",
        }
    )

    def fake_process_iter(_attrs: list[str]) -> list[FakePsutilProcess]:
        return [parent, child]

    monkeypatch.setattr(
        "integrity_monitor.core.process_monitor.psutil.process_iter", fake_process_iter
    )
    provider = PsutilProcessProvider(include_hashes=True, include_signatures=False)

    observations = provider.observations()

    by_pid = {observation.pid: observation for observation in observations}
    assert by_pid[11].ppid == 10
    assert by_pid[11].parent_name == "services.exe"
    assert by_pid[11].parent_exe == "C:\\Windows\\System32\\services.exe"
    assert by_pid[11].create_time == 123.5
    assert by_pid[11].sha256 == expected_hash


def test_signature_verifier_reports_unsupported_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_monitor_module, "is_windows", lambda: False)

    assert WindowsSignatureVerifier().verify("agent.exe") == "unsupported"


def test_signature_verifier_handles_powershell_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process_monitor_module, "is_windows", lambda: True)

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=5)

    monkeypatch.setattr("integrity_monitor.core.process_monitor.subprocess.run", fake_run)

    assert WindowsSignatureVerifier().verify("agent.exe") == "unknown"


def test_signature_verifier_uses_encoded_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_monitor_module, "is_windows", lambda: True)
    captured_args: list[str] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_args.extend(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="Valid\n", stderr="")

    monkeypatch.setattr("integrity_monitor.core.process_monitor.subprocess.run", fake_run)
    raw_path = "C:\\Temp\\bad' ; Stop-Service WinDefend ; '.exe"

    status = WindowsSignatureVerifier().verify(raw_path)

    assert status == "Valid"
    assert "-EncodedCommand" in captured_args
    assert "-Command" not in captured_args
    assert raw_path not in " ".join(captured_args)

from __future__ import annotations

from integrity_monitor.core.process_monitor import ProcessMonitor, ProcessObservation


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

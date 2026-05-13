"""Process monitoring for shared-PC venue environments."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import psutil

from integrity_monitor.utils.platform import (
    is_probably_writable_location,
    is_windows,
    normalize_path,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessObservation:
    """A normalized process snapshot."""

    pid: int
    ppid: int | None
    name: str
    exe: str | None
    username: str | None
    cmdline: list[str]
    cwd: str | None
    create_time: float | None
    parent_name: str | None = None
    parent_exe: str | None = None
    sha256: str | None = None
    signature_status: str | None = None


@dataclass(frozen=True)
class ProcessFinding:
    """A process anomaly finding."""

    rule_id: str
    severity: str
    title: str
    description: str
    pid: int
    process_name: str
    evidence: dict[str, Any] = field(default_factory=dict)


class ProcessProvider(Protocol):
    """Protocol for process providers used in tests and production."""

    def observations(self) -> list[ProcessObservation]:
        """Return process observations."""


class PsutilProcessProvider:
    """Collect process observations through psutil."""

    def __init__(self, *, include_hashes: bool = True, include_signatures: bool = False) -> None:
        self.include_hashes = include_hashes
        self.include_signatures = include_signatures
        self.signature_verifier = WindowsSignatureVerifier()

    def observations(self) -> list[ProcessObservation]:
        """Return current process observations."""

        processes: dict[int, psutil.Process] = {}
        observations: list[ProcessObservation] = []

        for process in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "username", "cmdline", "cwd", "create_time"]
        ):
            processes[int(process.info["pid"])] = process

        for process in processes.values():
            try:
                info = process.info
                ppid = self._int_or_none(info.get("ppid"))
                parent = processes.get(ppid) if ppid is not None else None
                exe = self._str_or_none(info.get("exe"))
                sha256_value = self._hash_exe(exe) if self.include_hashes and exe else None
                signature = (
                    self.signature_verifier.verify(exe)
                    if self.include_signatures and exe and is_windows()
                    else None
                )
                observations.append(
                    ProcessObservation(
                        pid=int(info["pid"]),
                        ppid=ppid,
                        name=str(info.get("name") or ""),
                        exe=exe,
                        username=self._str_or_none(info.get("username")),
                        cmdline=[str(item) for item in (info.get("cmdline") or [])],
                        cwd=self._str_or_none(info.get("cwd")),
                        create_time=self._float_or_none(info.get("create_time")),
                        parent_name=self._parent_attr(parent, "name"),
                        parent_exe=self._parent_attr(parent, "exe"),
                        sha256=sha256_value,
                        signature_status=signature,
                    )
                )
            except (
                psutil.AccessDenied,
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
                OSError,
            ) as exc:
                LOGGER.debug(
                    "process_observation_skipped", extra={"pid": process.pid, "error": str(exc)}
                )
        return observations

    @staticmethod
    def _str_or_none(value: object) -> str | None:
        return None if value is None else str(value)

    @staticmethod
    def _int_or_none(value: object) -> int | None:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if not isinstance(value, str):
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _float_or_none(value: object) -> float | None:
        if value is None:
            return None
        if isinstance(value, int | float | str):
            try:
                return float(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def _parent_attr(parent: psutil.Process | None, attr: str) -> str | None:
        if parent is None:
            return None
        try:
            value = getattr(parent, attr)()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        return None if value is None else str(value)

    @staticmethod
    def _hash_exe(exe: str) -> str | None:
        path = Path(exe)
        if not path.is_file():
            return None
        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None


class WindowsSignatureVerifier:
    """Verify Authenticode status through PowerShell when available."""

    def verify(self, path: str) -> str:
        """Return a normalized signature status for a path."""

        if not is_windows():
            return "unsupported"
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOGGER.debug("signature_verification_failed", extra={"path": path, "error": str(exc)})
            return "unknown"
        status = completed.stdout.strip()
        return status or "unknown"


class ProcessMonitor:
    """Analyze process state for anomalies relevant to gaming venues."""

    def __init__(
        self,
        *,
        provider: ProcessProvider | None = None,
        expected_hashes: dict[str, str] | None = None,
        allowed_writable_processes: set[str] | None = None,
        protected_process_keywords: set[str] | None = None,
        suspicious_children: set[str] | None = None,
        include_unsigned_check: bool = True,
    ) -> None:
        """Initialize the process monitor.

        Args:
            provider: Process provider for production or tests.
            expected_hashes: Map of normalized executable path to approved SHA-256.
            allowed_writable_processes: Process names allowed from writable paths.
            protected_process_keywords: Keywords identifying billing or control processes.
            suspicious_children: Child process names suspicious under protected parents.
            include_unsigned_check: Whether unsigned Windows process findings are enabled.
        """

        self.provider = provider or PsutilProcessProvider(include_signatures=include_unsigned_check)
        self.expected_hashes = {
            normalize_path(k).lower(): v.lower() for k, v in (expected_hashes or {}).items()
        }
        self.allowed_writable_processes = {
            item.lower() for item in (allowed_writable_processes or set())
        }
        self.protected_process_keywords = {
            item.lower()
            for item in (
                protected_process_keywords
                or {
                    "billing",
                    "cashier",
                    "clientagent",
                    "restore",
                    "rollback",
                    "watchdog",
                    "wazuh",
                    "sysmon",
                }
            )
        }
        self.suspicious_children = {
            item.lower()
            for item in (
                suspicious_children
                or {
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "wscript.exe",
                    "cscript.exe",
                    "reg.exe",
                    "sc.exe",
                    "taskkill.exe",
                    "wmic.exe",
                    "rundll32.exe",
                }
            )
        }
        self.include_unsigned_check = include_unsigned_check

    def scan(self) -> list[ProcessFinding]:
        """Collect and analyze current processes."""

        observations = self.provider.observations()
        findings: list[ProcessFinding] = []
        by_pid = {observation.pid: observation for observation in observations}

        for observation in observations:
            findings.extend(self._check_writable_execution(observation))
            findings.extend(self._check_signature(observation))
            findings.extend(self._check_hash_baseline(observation))
            findings.extend(self._check_parent_child(observation, by_pid))
            findings.extend(self._check_deleted_or_missing_exe(observation))
        return findings

    def _check_writable_execution(self, observation: ProcessObservation) -> list[ProcessFinding]:
        if not observation.exe:
            return []
        name = observation.name.lower()
        if name in self.allowed_writable_processes:
            return []
        if not is_probably_writable_location(observation.exe):
            return []
        return [
            ProcessFinding(
                rule_id="process.writable_path_execution",
                severity="medium",
                title="Process running from writable location",
                description=(
                    "A process executable path is located in a user-writable "
                    "or temporary directory."
                ),
                pid=observation.pid,
                process_name=observation.name,
                evidence={
                    "exe": observation.exe,
                    "username": observation.username,
                    "cmdline": observation.cmdline,
                },
            )
        ]

    def _check_signature(self, observation: ProcessObservation) -> list[ProcessFinding]:
        if not self.include_unsigned_check or not is_windows() or not observation.exe:
            return []
        status = (observation.signature_status or "unknown").lower()
        if status in {"valid", "unsupported"}:
            return []
        if not self._is_sensitive_process(observation) and not is_probably_writable_location(
            observation.exe
        ):
            return []
        return [
            ProcessFinding(
                rule_id="process.unsigned_sensitive_process",
                severity="medium",
                title="Unsigned or unverifiable process in sensitive context",
                description=(
                    "A process is unsigned or has an unverifiable signature "
                    "in a sensitive role or path."
                ),
                pid=observation.pid,
                process_name=observation.name,
                evidence={"exe": observation.exe, "signature_status": observation.signature_status},
            )
        ]

    def _check_hash_baseline(self, observation: ProcessObservation) -> list[ProcessFinding]:
        if not observation.exe or not observation.sha256:
            return []
        normalized = normalize_path(observation.exe).lower()
        expected = self.expected_hashes.get(normalized)
        if expected is None or expected == observation.sha256.lower():
            return []
        return [
            ProcessFinding(
                rule_id="process.hash_baseline_drift",
                severity="high",
                title="Process executable hash differs from baseline",
                description=(
                    "A running process executable differs from the known-good hash baseline."
                ),
                pid=observation.pid,
                process_name=observation.name,
                evidence={
                    "exe": observation.exe,
                    "expected": expected,
                    "actual": observation.sha256,
                },
            )
        ]

    def _check_parent_child(
        self,
        observation: ProcessObservation,
        by_pid: dict[int, ProcessObservation],
    ) -> list[ProcessFinding]:
        parent = by_pid.get(observation.ppid or -1)
        parent_name = (parent.name if parent else observation.parent_name or "").lower()
        parent_exe = (parent.exe if parent else observation.parent_exe) or ""
        child_name = observation.name.lower()
        parent_context = f"{parent_name} {parent_exe}".lower()

        if child_name not in self.suspicious_children:
            return []
        if not any(keyword in parent_context for keyword in self.protected_process_keywords):
            return []
        return [
            ProcessFinding(
                rule_id="process.suspicious_child_of_protected_process",
                severity="high",
                title="Suspicious child process from venue control software",
                description=(
                    "A billing, restoration, logging, or control process launched "
                    "a suspicious child process."
                ),
                pid=observation.pid,
                process_name=observation.name,
                evidence={
                    "parent_name": parent_name,
                    "parent_exe": parent_exe,
                    "cmdline": observation.cmdline,
                },
            )
        ]

    def _check_deleted_or_missing_exe(
        self, observation: ProcessObservation
    ) -> list[ProcessFinding]:
        if not observation.exe:
            return []
        exe = observation.exe
        if os.path.exists(exe):
            return []
        severity = "medium" if self._is_sensitive_process(observation) else "low"
        return [
            ProcessFinding(
                rule_id="process.missing_executable_path",
                severity=severity,
                title="Running process executable path is missing",
                description="The executable path for a running process is not present on disk.",
                pid=observation.pid,
                process_name=observation.name,
                evidence={"exe": exe, "cmdline": observation.cmdline},
            )
        ]

    def _is_sensitive_process(self, observation: ProcessObservation) -> bool:
        context = " ".join(
            [
                observation.name,
                observation.exe or "",
                " ".join(observation.cmdline),
            ]
        ).lower()
        return any(keyword in context for keyword in self.protected_process_keywords)

"""Reusable heuristic detectors."""

from __future__ import annotations

from pathlib import Path

from integrity_monitor.detectors.base import DetectionFinding, Detector
from integrity_monitor.utils.platform import is_probably_writable_location


class HeuristicDetector(Detector):
    """Simple defensive heuristics used by multiple monitor components."""

    def __init__(self, suspicious_extensions: set[str] | None = None) -> None:
        self.suspicious_extensions = suspicious_extensions or {
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
        }

    def analyze(self, item: object) -> list[DetectionFinding]:
        """Analyze a path-like item for generic risky traits."""

        path = Path(str(item))
        findings: list[DetectionFinding] = []
        if path.suffix.lower() in self.suspicious_extensions and is_probably_writable_location(
            path
        ):
            findings.append(
                DetectionFinding(
                    rule_id="heuristic.writable_executable_path",
                    severity="medium",
                    title="Executable in writable location",
                    description="A script or executable was observed in a user-writable location.",
                    evidence={"path": str(path)},
                )
            )
        if any(part.lower() in {"temp", "tmp", "downloads"} for part in path.parts):
            findings.append(
                DetectionFinding(
                    rule_id="heuristic.transient_path",
                    severity="low",
                    title="Transient path observed",
                    description=(
                        "The path is located in a transient directory that should "
                        "not host trusted components."
                    ),
                    evidence={"path": str(path)},
                )
            )
        return findings

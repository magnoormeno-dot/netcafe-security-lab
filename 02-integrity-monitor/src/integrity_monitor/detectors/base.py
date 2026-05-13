"""Detector base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionFinding:
    """A detector finding."""

    rule_id: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    """Abstract detector interface."""

    @abstractmethod
    def analyze(self, item: object) -> list[DetectionFinding]:
        """Analyze an item and return findings."""

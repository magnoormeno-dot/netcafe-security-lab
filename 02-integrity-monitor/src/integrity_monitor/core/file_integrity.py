"""File integrity scanning and baseline comparison."""

from __future__ import annotations

import fnmatch
import glob
import hashlib
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, cast

from integrity_monitor.core.baseline import (
    BaselineDiff,
    BaselineManager,
    BaselineVersion,
    FileRecord,
)
from integrity_monitor.detectors.base import DetectionFinding
from integrity_monitor.detectors.heuristics import HeuristicDetector
from integrity_monitor.utils.platform import normalize_path


class HashLike(Protocol):
    """Common hashing interface for hashlib and BLAKE3 objects."""

    def update(self, data: bytes) -> object:
        """Update the digest with bytes."""

    def hexdigest(self) -> str:
        """Return the hex digest."""


class Blake3Module(Protocol):
    """Subset of the BLAKE3 module used by the monitor."""

    def blake3(self) -> HashLike:
        """Return a new BLAKE3 hasher."""


try:
    import blake3 as _blake3_module
except ImportError:  # pragma: no cover - exercised only without optional dependency
    blake3_module: Blake3Module | None = None
else:
    blake3_module = cast(Blake3Module, _blake3_module)

LOGGER = logging.getLogger(__name__)
HashAlgorithm = Literal["sha256", "blake3"]


@dataclass(frozen=True)
class ScanTarget:
    """A file, directory, or glob target."""

    pattern: str
    recursive: bool = True


@dataclass(frozen=True)
class FileChange:
    """A normalized file change suitable for alerting."""

    path: str
    change_type: Literal["added", "removed", "modified"]
    old_hashes: dict[str, str] = field(default_factory=dict)
    new_hashes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class IntegrityScanResult:
    """Result of an integrity scan."""

    records: list[FileRecord]
    diff: BaselineDiff | None = None
    findings: list[DetectionFinding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def changes(self) -> list[FileChange]:
        """Return file changes derived from the baseline diff."""

        if self.diff is None:
            return []
        changes: list[FileChange] = []
        for record in self.diff.added:
            changes.append(
                FileChange(path=record.path, change_type="added", new_hashes=record.hashes)
            )
        for record in self.diff.removed:
            changes.append(
                FileChange(path=record.path, change_type="removed", old_hashes=record.hashes)
            )
        for old, new in self.diff.modified:
            changes.append(
                FileChange(
                    path=new.path,
                    change_type="modified",
                    old_hashes=old.hashes,
                    new_hashes=new.hashes,
                )
            )
        return changes


@dataclass
class _CacheEntry:
    size: int
    mtime_ns: int
    hashes: dict[str, str]


class FileIntegrityMonitor:
    """Scan files, calculate hashes, and compare results to baselines."""

    def __init__(
        self,
        targets: Sequence[ScanTarget | str | Path],
        *,
        algorithms: Sequence[HashAlgorithm] | None = None,
        excludes: list[str] | None = None,
        follow_symlinks: bool = False,
        chunk_size: int = 1024 * 1024,
        baseline_manager: BaselineManager | None = None,
        detector: HeuristicDetector | None = None,
    ) -> None:
        """Initialize the monitor.

        Args:
            targets: Files, directories, or glob patterns to scan.
            algorithms: Hash algorithms to calculate.
            excludes: Glob patterns to exclude.
            follow_symlinks: Whether to follow symlinks during directory scans.
            chunk_size: File read chunk size.
            baseline_manager: Optional baseline manager used for compare/create.
            detector: Optional heuristic detector for risky file paths.
        """

        self.targets = [self._coerce_target(target) for target in targets]
        self.algorithms = algorithms or ["sha256"]
        self.excludes = excludes or []
        self.follow_symlinks = follow_symlinks
        self.chunk_size = chunk_size
        self.baseline_manager = baseline_manager
        self.detector = detector or HeuristicDetector()
        self._cache: dict[str, _CacheEntry] = {}
        self._validate_algorithms()

    @staticmethod
    def _coerce_target(target: ScanTarget | str | Path) -> ScanTarget:
        if isinstance(target, ScanTarget):
            return target
        return ScanTarget(pattern=str(target))

    def _validate_algorithms(self) -> None:
        supported = {"sha256", "blake3"}
        unknown = set(self.algorithms) - supported
        if unknown:
            raise ValueError(f"Unsupported hash algorithms: {', '.join(sorted(unknown))}")
        if "blake3" in self.algorithms and blake3_module is None:
            raise RuntimeError("BLAKE3 hashing requested but the blake3 package is not installed")

    def create_baseline(self, *, metadata: dict[str, object] | None = None) -> BaselineVersion:
        """Scan targets and create a persisted baseline version."""

        if self.baseline_manager is None:
            raise ValueError("baseline_manager is required to create a baseline")
        result = self.scan()
        if result.errors:
            LOGGER.warning(
                "baseline_created_with_scan_errors", extra={"error_count": len(result.errors)}
            )
        return self.baseline_manager.create_version(result.records, metadata=dict(metadata or {}))

    def scan(self, *, baseline: BaselineVersion | None = None) -> IntegrityScanResult:
        """Scan configured targets and optionally compare with a baseline."""

        records: list[FileRecord] = []
        findings: list[DetectionFinding] = []
        errors: dict[str, str] = {}
        selected_baseline = self._resolve_baseline(baseline)
        use_cache = selected_baseline is None

        for path in self.iter_files():
            try:
                record = self.record_file(path, use_cache=use_cache)
            except OSError as exc:
                normalized = normalize_path(path)
                errors[normalized] = str(exc)
                LOGGER.warning("file_scan_error", extra={"path": normalized, "error": str(exc)})
                continue
            records.append(record)
            findings.extend(self.detector.analyze(record.path))

        records.sort(key=lambda item: item.path)
        diff = None
        if selected_baseline is not None and self.baseline_manager is not None:
            diff = self.baseline_manager.diff_records(selected_baseline, records)
        elif selected_baseline is not None:
            diff = BaselineManager("unused").diff_records(selected_baseline, records)

        return IntegrityScanResult(records=records, diff=diff, findings=findings, errors=errors)

    def _resolve_baseline(self, baseline: BaselineVersion | None) -> BaselineVersion | None:
        """Return the explicit or latest baseline for this scan."""

        if baseline is not None:
            return baseline
        if self.baseline_manager is None:
            return None
        try:
            return self.baseline_manager.latest_version()
        except FileNotFoundError:
            return None

    def iter_files(self) -> list[Path]:
        """Return sorted unique file paths for all configured targets."""

        paths: set[Path] = set()
        for target in self.targets:
            for path in self._expand_target(target):
                if self._should_include(path):
                    paths.add(path)
        return sorted(paths, key=lambda item: str(item).lower())

    def _expand_target(self, target: ScanTarget) -> list[Path]:
        pattern = os.path.expanduser(target.pattern)
        if self._looks_like_glob(pattern):
            return [
                Path(match)
                for match in glob.glob(pattern, recursive=target.recursive)
                if Path(match).is_file()
            ]

        path = Path(pattern)
        if path.is_file():
            return [path]
        if path.is_dir():
            iterator = path.rglob("*") if target.recursive else path.glob("*")
            return [
                item
                for item in iterator
                if item.is_file() and (self.follow_symlinks or not item.is_symlink())
            ]
        return []

    @staticmethod
    def _looks_like_glob(pattern: str) -> bool:
        return any(marker in pattern for marker in "*?[]")

    def _should_include(self, path: Path) -> bool:
        normalized = normalize_path(path)
        for pattern in self.excludes:
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(path.name, pattern):
                return False
        return not (path.is_symlink() and not self.follow_symlinks)

    def record_file(self, path: str | Path, *, use_cache: bool = True) -> FileRecord:
        """Create a file record, using the incremental cache when possible."""

        file_path = Path(path)
        stat = file_path.stat()
        normalized = normalize_path(file_path)
        cached = self._cache.get(normalized)
        if (
            use_cache
            and cached
            and cached.size == stat.st_size
            and cached.mtime_ns == stat.st_mtime_ns
        ):
            hashes = dict(cached.hashes)
        else:
            hashes = self.hash_file(file_path)
            self._cache[normalized] = _CacheEntry(
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
                hashes=dict(hashes),
            )
        return FileRecord(
            path=normalized,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            hashes=hashes,
            mode=stat.st_mode,
        )

    def hash_file(self, path: str | Path) -> dict[str, str]:
        """Calculate configured hashes for a file."""

        hashers = self._new_hashers()
        with Path(path).open("rb") as handle:
            self._feed_hashers(handle, hashers)
        return {name: hasher.hexdigest() for name, hasher in hashers.items()}

    def _new_hashers(self) -> dict[str, HashLike]:
        hashers: dict[str, HashLike] = {}
        for algorithm in self.algorithms:
            if algorithm == "sha256":
                hashers[algorithm] = hashlib.sha256()
            elif algorithm == "blake3":
                if blake3_module is None:
                    raise RuntimeError("BLAKE3 hashing requested but unavailable")
                hashers[algorithm] = blake3_module.blake3()
            else:  # pragma: no cover - guarded by validation
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return hashers

    def _feed_hashers(self, handle: BinaryIO, hashers: dict[str, HashLike]) -> None:
        while True:
            chunk = handle.read(self.chunk_size)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)

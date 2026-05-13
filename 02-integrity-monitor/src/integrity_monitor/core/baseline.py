"""Baseline management for file integrity monitoring.

The baseline manager stores versioned file records in JSON or SQLite. It can
optionally sign each version with HMAC-SHA256 so operators can detect baseline
tampering. The HMAC key must be protected outside customer-writable paths.
"""

from __future__ import annotations

import hmac
import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

LOGGER = logging.getLogger(__name__)
StorageKind = Literal["json", "sqlite"]


@dataclass(frozen=True)
class FileRecord:
    """A single file state captured in a baseline."""

    path: str
    size: int
    mtime_ns: int
    hashes: dict[str, str]
    mode: int | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FileRecord:
        """Build a file record from untrusted persisted data."""

        return cls(
            path=str(value["path"]),
            size=int(value["size"]),
            mtime_ns=int(value["mtime_ns"]),
            hashes={str(k): str(v) for k, v in dict(value["hashes"]).items()},
            mode=None if value.get("mode") is None else int(value["mode"]),
        )


@dataclass(frozen=True)
class BaselineVersion:
    """A versioned collection of file records."""

    version_id: str
    created_at: str
    records: dict[str, FileRecord]
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str | None = None

    @classmethod
    def create(
        cls,
        records: list[FileRecord],
        *,
        metadata: dict[str, Any] | None = None,
        version_id: str | None = None,
    ) -> BaselineVersion:
        """Create a new baseline version."""

        normalized = {record.path: record for record in sorted(records, key=lambda item: item.path)}
        return cls(
            version_id=version_id or str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(),
            records=normalized,
            metadata=metadata or {},
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BaselineVersion:
        """Build a baseline version from persisted data."""

        records_raw = dict(value.get("records", {}))
        records = {str(path): FileRecord.from_dict(record) for path, record in records_raw.items()}
        return cls(
            version_id=str(value["version_id"]),
            created_at=str(value["created_at"]),
            records=records,
            metadata=dict(value.get("metadata", {})),
            signature=value.get("signature"),
        )

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        """Serialize the baseline version."""

        payload: dict[str, Any] = {
            "version_id": self.version_id,
            "created_at": self.created_at,
            "records": {path: asdict(record) for path, record in sorted(self.records.items())},
            "metadata": self.metadata,
        }
        if include_signature:
            payload["signature"] = self.signature
        return payload

    def with_signature(self, signature: str | None) -> BaselineVersion:
        """Return a copy with a new signature."""

        return BaselineVersion(
            version_id=self.version_id,
            created_at=self.created_at,
            records=self.records,
            metadata=self.metadata,
            signature=signature,
        )


@dataclass(frozen=True)
class BaselineDiff:
    """A comparison between a baseline and current records."""

    added: list[FileRecord]
    removed: list[FileRecord]
    modified: list[tuple[FileRecord, FileRecord]]
    unchanged: list[FileRecord]

    def has_changes(self) -> bool:
        """Return whether the diff contains any added, removed, or modified files."""

        return bool(self.added or self.removed or self.modified)


class BaselineIntegrityError(RuntimeError):
    """Raised when a baseline signature cannot be verified."""


class BaselineManager:
    """Manage signed, versioned file baselines."""

    def __init__(
        self,
        store_path: str | Path,
        *,
        storage: StorageKind | None = None,
        hmac_key: bytes | None = None,
    ) -> None:
        """Initialize a baseline manager.

        Args:
            store_path: JSON or SQLite storage path.
            storage: Explicit storage kind. If omitted, infer from suffix.
            hmac_key: Optional HMAC key used to sign and verify baseline versions.
        """

        self.store_path = Path(store_path)
        self.storage = storage or self._infer_storage(self.store_path)
        self.hmac_key = hmac_key
        if self.storage not in {"json", "sqlite"}:
            raise ValueError(f"Unsupported baseline storage kind: {self.storage}")

    @staticmethod
    def _infer_storage(path: Path) -> StorageKind:
        if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            return "sqlite"
        return "json"

    def create_version(
        self,
        records: list[FileRecord],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> BaselineVersion:
        """Create, sign, and persist a baseline version."""

        version = BaselineVersion.create(records, metadata=metadata)
        signed = self.sign_version(version)
        self.save_version(signed)
        LOGGER.info("baseline_version_created", extra={"version_id": signed.version_id})
        return signed

    def sign_version(self, version: BaselineVersion) -> BaselineVersion:
        """Return a signed copy of a baseline version."""

        if self.hmac_key is None:
            return version.with_signature(None)
        payload = self._canonical_payload(version)
        digest = hmac.new(self.hmac_key, payload, sha256).hexdigest()
        return version.with_signature(digest)

    def verify_version(self, version: BaselineVersion) -> bool:
        """Verify a baseline version signature.

        Unsigned baselines are considered valid only when the manager has no
        HMAC key configured. If a key is configured, missing signatures fail.
        """

        if self.hmac_key is None:
            return True
        if not version.signature:
            return False
        expected = hmac.new(self.hmac_key, self._canonical_payload(version), sha256).hexdigest()
        return hmac.compare_digest(expected, version.signature)

    def require_valid(self, version: BaselineVersion) -> None:
        """Raise when a baseline version fails signature verification."""

        if not self.verify_version(version):
            raise BaselineIntegrityError(
                f"Baseline version {version.version_id} failed verification"
            )

    def save_version(self, version: BaselineVersion) -> None:
        """Persist a baseline version."""

        self.require_valid(version)
        if self.storage == "json":
            self._save_json(version)
        else:
            self._save_sqlite(version)

    def list_versions(self) -> list[BaselineVersion]:
        """Return all persisted baseline versions sorted by creation time."""

        versions = (
            self._load_json_versions() if self.storage == "json" else self._load_sqlite_versions()
        )
        return sorted(versions, key=lambda item: item.created_at)

    def latest_version(self) -> BaselineVersion:
        """Return the newest baseline version."""

        versions = self.list_versions()
        if not versions:
            raise FileNotFoundError(f"No baseline versions found in {self.store_path}")
        latest = versions[-1]
        self.require_valid(latest)
        return latest

    def get_version(self, version_id: str) -> BaselineVersion:
        """Return a specific baseline version."""

        for version in self.list_versions():
            if version.version_id == version_id:
                self.require_valid(version)
                return version
        raise KeyError(f"Baseline version not found: {version_id}")

    def rollback(self, version_id: str) -> BaselineVersion:
        """Create a new latest version from an older version."""

        previous = self.get_version(version_id)
        metadata = dict(previous.metadata)
        metadata["rolled_back_from"] = previous.version_id
        metadata["rollback_created_at"] = datetime.now(timezone.utc).isoformat()
        version = BaselineVersion.create(list(previous.records.values()), metadata=metadata)
        signed = self.sign_version(version)
        self.save_version(signed)
        return signed

    def diff_records(
        self,
        baseline: BaselineVersion,
        current_records: list[FileRecord],
    ) -> BaselineDiff:
        """Compare a baseline with current file records."""

        self.require_valid(baseline)
        current = {record.path: record for record in current_records}
        baseline_paths = set(baseline.records)
        current_paths = set(current)
        added = [current[path] for path in sorted(current_paths - baseline_paths)]
        removed = [baseline.records[path] for path in sorted(baseline_paths - current_paths)]
        unchanged: list[FileRecord] = []
        modified: list[tuple[FileRecord, FileRecord]] = []

        for path in sorted(baseline_paths & current_paths):
            old = baseline.records[path]
            new = current[path]
            if old.hashes == new.hashes and old.size == new.size:
                unchanged.append(new)
            else:
                modified.append((old, new))
        return BaselineDiff(added=added, removed=removed, modified=modified, unchanged=unchanged)

    def _canonical_payload(self, version: BaselineVersion) -> bytes:
        payload = version.to_dict(include_signature=False)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )

    def _save_json(self, version: BaselineVersion) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        versions = self._load_json_versions()
        versions = [item for item in versions if item.version_id != version.version_id]
        versions.append(version)
        payload = {"schema_version": 1, "versions": [item.to_dict() for item in versions]}
        temporary = self.store_path.with_suffix(self.store_path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(self.store_path)

    def _load_json_versions(self) -> list[BaselineVersion]:
        if not self.store_path.exists():
            return []
        try:
            payload = json.loads(self.store_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid baseline JSON: {self.store_path}") from exc
        versions_raw = payload.get("versions", [])
        if not isinstance(versions_raw, list):
            raise ValueError("Baseline JSON must contain a versions list")
        return [BaselineVersion.from_dict(dict(item)) for item in versions_raw]

    def _connect(self) -> sqlite3.Connection:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.store_path)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline_versions (
                version_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        return connection

    def _save_sqlite(self, version: BaselineVersion) -> None:
        payload = json.dumps(version.to_dict(), sort_keys=True)
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT OR REPLACE INTO baseline_versions(version_id, created_at, payload)
                VALUES (?, ?, ?)
                """,
                (version.version_id, version.created_at, payload),
            )
            connection.commit()
        finally:
            connection.close()

    def _load_sqlite_versions(self) -> list[BaselineVersion]:
        if not self.store_path.exists():
            return []
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT payload FROM baseline_versions ORDER BY created_at ASC"
            ).fetchall()
        finally:
            connection.close()
        versions: list[BaselineVersion] = []
        for (payload,) in rows:
            versions.append(BaselineVersion.from_dict(json.loads(str(payload))))
        return versions

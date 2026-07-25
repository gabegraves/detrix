"""Local SQLite persistence with immutable verdict and event history."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from detrix.admission import AdmissionPacket
from detrix.canonical import canonical_digest, canonical_json

EVENT_SCHEMA_VERSION = 1


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, path: str | Path = ".detrix/store.db") -> None:
        self.path = Path(path)
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        parent = self.path.parent
        for candidate in (parent, *parent.parents):
            if (candidate.exists() or candidate.is_symlink()) and stat.S_ISLNK(
                candidate.lstat().st_mode
            ):
                raise StoreError(f"store path contains a symlinked directory: {candidate}")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != os.getuid()
        ):
            raise StoreError(
                f"store parent must be a real directory owned by the current user: {parent}"
            )
        parent.chmod(0o700)
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise StoreError(
                    f"store must be a regular file owned by the current user: {self.path}"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS traces (
                    trace_id TEXT PRIMARY KEY,
                    fetched_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trace_snapshots (
                    trace_hash TEXT PRIMARY KEY,
                    raw_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS config_snapshots (
                    config_hash TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    config_event_id INTEGER NOT NULL,
                    trace_hash TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    packet_json TEXT NOT NULL,
                    UNIQUE(trace_id, config_event_id, trace_hash)
                );
                CREATE TABLE IF NOT EXISTS config_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    prior_config_hash TEXT,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    old_verdict_id INTEGER NOT NULL,
                    new_verdict_id INTEGER NOT NULL,
                    old_config_hash TEXT NOT NULL,
                    new_config_hash TEXT NOT NULL,
                    old_trace_hash TEXT NOT NULL,
                    new_trace_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(event_type, old_verdict_id, new_verdict_id)
                );
                CREATE TABLE IF NOT EXISTS pushes (
                    trace_id TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    trace_hash TEXT NOT NULL,
                    score_name TEXT NOT NULL,
                    score_id TEXT NOT NULL,
                    pushed_at TEXT NOT NULL,
                    PRIMARY KEY(trace_id, config_hash, trace_hash, score_name)
                );
                """
            )
            self._backfill_trace_snapshots(connection)
        self.path.chmod(0o600)

    def _backfill_trace_snapshots(self, connection: sqlite3.Connection) -> None:
        # ponytail: re-scans all traces on every open (INSERT OR IGNORE, so cheap
        # once caught up). Fine at this store's scale; add a backfill marker if
        # trace counts get large enough to matter.
        rows = connection.execute("SELECT raw_json, fetched_at FROM traces").fetchall()
        for row in rows:
            packet = json.loads(row["raw_json"])
            connection.execute(
                """INSERT OR IGNORE INTO trace_snapshots(trace_hash, raw_json, first_seen_at)
                   VALUES (?, ?, ?)""",
                (canonical_digest(packet), row["raw_json"], row["fetched_at"]),
            )

    def upsert_trace(self, packet: dict[str, Any], fetched_at: str | None = None) -> None:
        trace = packet.get("trace")
        trace_id = trace.get("id") if isinstance(trace, dict) else None
        if not isinstance(trace_id, str) or not trace_id:
            raise StoreError("trace packet requires trace.id")
        raw = canonical_json(packet)
        when = fetched_at or _now()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO traces(trace_id, fetched_at, raw_json) VALUES (?, ?, ?)
                   ON CONFLICT(trace_id) DO UPDATE SET
                     fetched_at = excluded.fetched_at,
                     raw_json = excluded.raw_json""",
                (trace_id, when, raw),
            )
            connection.execute(
                """INSERT OR IGNORE INTO trace_snapshots(trace_hash, raw_json, first_seen_at)
                   VALUES (?, ?, ?)""",
                (canonical_digest(packet), raw, when),
            )

    def list_traces(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT trace_id, fetched_at, raw_json FROM traces ORDER BY trace_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_trace_snapshot(self, trace_hash: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT raw_json FROM trace_snapshots WHERE trace_hash = ?",
                (trace_hash,),
            ).fetchone()
        return row["raw_json"] if row is not None else None

    def save_verdict(self, packet: AdmissionPacket) -> bool:
        serialized = packet.model_dump_json()
        trace_hash = _packet_trace_hash(packet)
        config_event_id = self.activate_config(packet.config_hash)
        with self._connect() as connection:
            old_row = connection.execute(
                """SELECT id, config_hash, trace_hash FROM verdicts
                   WHERE trace_id = ? ORDER BY id DESC LIMIT 1""",
                (packet.run_id,),
            ).fetchone()
            cursor = connection.execute(
                """INSERT OR IGNORE INTO verdicts
                   (trace_id, config_hash, config_event_id, trace_hash,
                    evaluated_at, decision, packet_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    packet.run_id,
                    packet.config_hash,
                    config_event_id,
                    trace_hash,
                    _now(),
                    packet.admission_decision.value,
                    serialized,
                ),
            )
            inserted = cursor.rowcount == 1
            if inserted and old_row is not None:
                new_verdict_id = int(cursor.lastrowid)
                connection.execute(
                    """INSERT INTO events
                       (schema_version, event_type, trace_id, old_verdict_id,
                        new_verdict_id, old_config_hash, new_config_hash,
                        old_trace_hash, new_trace_hash, created_at, details_json)
                       VALUES (?, 'REPLAY_REQUIRED', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        EVENT_SCHEMA_VERSION,
                        packet.run_id,
                        old_row["id"],
                        new_verdict_id,
                        old_row["config_hash"],
                        packet.config_hash,
                        old_row["trace_hash"],
                        trace_hash,
                        _now(),
                        json.dumps(
                            {
                                "config_changed": old_row["config_hash"]
                                != packet.config_hash,
                                "trace_changed": old_row["trace_hash"] != trace_hash,
                            },
                            sort_keys=True,
                        ),
                    ),
                )
        return inserted

    def activate_config(self, config_hash: str) -> int:
        """Return the append-only activation event for the current config."""

        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, schema_version, event_type, config_hash
                   FROM config_events ORDER BY id"""
            ).fetchall()
            _validate_event_versions(rows)
            current, current_event_id = _current_config_state(rows)
            if current == config_hash:
                if current_event_id is None:
                    raise StoreError(f"active config has no activation event: {config_hash}")
                return current_event_id
            previously_active = any(
                row["config_hash"] == config_hash
                and row["event_type"] in {"CONFIG_PROMOTED", "CONFIG_REVERTED"}
                for row in rows
            )
            event_type = "CONFIG_REVERTED" if previously_active else "CONFIG_PROMOTED"
            if current is not None:
                connection.execute(
                    """INSERT INTO config_events
                       (schema_version, event_type, config_hash, prior_config_hash,
                        created_at, details_json)
                       VALUES (?, 'CONFIG_INVALIDATED', ?, ?, ?, '{}')""",
                    (EVENT_SCHEMA_VERSION, current, current, _now()),
                )
            cursor = connection.execute(
                """INSERT INTO config_events
                   (schema_version, event_type, config_hash, prior_config_hash,
                    created_at, details_json)
                   VALUES (?, ?, ?, ?, ?, '{}')""",
                (EVENT_SCHEMA_VERSION, event_type, config_hash, current, _now()),
            )
            return int(cursor.lastrowid)

    def save_config_snapshot(self, config_hash: str, content: str) -> None:
        """Persist the exact content a config_hash was computed over. Idempotent."""

        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO config_snapshots(config_hash, content, stored_at)
                   VALUES (?, ?, ?)""",
                (config_hash, content, _now()),
            )

    def get_config_snapshot(self, config_hash: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT content FROM config_snapshots WHERE config_hash = ?",
                (config_hash,),
            ).fetchone()
        return row["content"] if row is not None else None

    def invalidate_config(self, config_hash: str) -> None:
        """Append invalidation without deleting config or verdict history."""

        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, schema_version, event_type, config_hash
                   FROM config_events ORDER BY id"""
            ).fetchall()
            _validate_event_versions(rows)
            current, _ = _current_config_state(rows)
            connection.execute(
                """INSERT INTO config_events
                   (schema_version, event_type, config_hash, prior_config_hash,
                    created_at, details_json)
                   VALUES (?, 'CONFIG_INVALIDATED', ?, ?, ?, '{}')""",
                (EVENT_SCHEMA_VERSION, config_hash, current, _now()),
            )

    def list_config_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT schema_version, event_type, config_hash, prior_config_hash
                   FROM config_events ORDER BY id"""
            ).fetchall()
        _validate_event_versions(rows)
        return [dict(row) for row in rows]

    def get_verdict(self, trace_id: str, config_hash: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT v.trace_id, v.config_hash, v.config_event_id, v.trace_hash,
                          v.evaluated_at, v.decision,
                          v.packet_json,
                          EXISTS(
                            SELECT 1 FROM events e
                            WHERE e.old_verdict_id = v.id
                              AND e.event_type = 'REPLAY_REQUIRED'
                          ) AS stale
                   FROM verdicts v WHERE v.id = (
                       SELECT MAX(id) FROM verdicts
                       WHERE trace_id = ? AND config_hash = ?
                   )""",
                (trace_id, config_hash),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        if result["config_event_id"] != self._current_config_event_id():
            result["stale"] = 1
        return result

    def list_verdicts(self, *, latest_only: bool = False) -> list[dict[str, Any]]:
        query = """SELECT v.id, v.trace_id, v.config_hash, v.config_event_id,
                          v.trace_hash, v.evaluated_at,
                          v.decision, v.packet_json,
                          EXISTS(
                            SELECT 1 FROM events e
                            WHERE e.old_verdict_id = v.id
                              AND e.event_type = 'REPLAY_REQUIRED'
                          ) AS stale
                   FROM verdicts v"""
        if latest_only:
            query += " WHERE v.id IN (SELECT MAX(id) FROM verdicts GROUP BY trace_id)"
        query += " ORDER BY v.id"
        with self._connect() as connection:
            rows = connection.execute(query).fetchall()
        current_event_id = self._current_config_event_id()
        results = [dict(row) for row in rows]
        for result in results:
            if result["config_event_id"] != current_event_id:
                result["stale"] = 1
        return results

    def _current_config_event_id(self) -> int | None:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, schema_version, event_type, config_hash
                   FROM config_events ORDER BY id"""
            ).fetchall()
        _validate_event_versions(rows)
        _, event_id = _current_config_state(rows)
        return event_id

    def list_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT schema_version, event_type, trace_id,
                          old_config_hash, new_config_hash
                   FROM events ORDER BY id"""
            ).fetchall()
        events = [dict(row) for row in rows]
        unknown = [event["schema_version"] for event in events if event["schema_version"] != 1]
        if unknown:
            raise StoreError(f"unsupported event schema_version: {unknown[0]}")
        return events

    def was_pushed(
        self, trace_id: str, config_hash: str, trace_hash: str, score_name: str
    ) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM pushes
                   WHERE trace_id = ? AND config_hash = ? AND trace_hash = ?
                     AND score_name = ?""",
                (trace_id, config_hash, trace_hash, score_name),
            ).fetchone()
        return row is not None

    def record_push(
        self,
        trace_id: str,
        config_hash: str,
        trace_hash: str,
        score_name: str,
        score_id: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO pushes
                   (trace_id, config_hash, trace_hash, score_name, score_id, pushed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (trace_id, config_hash, trace_hash, score_name, score_id, _now()),
            )

    def push_receipts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT trace_id, config_hash, trace_hash, score_name, score_id, pushed_at
                   FROM pushes ORDER BY trace_id, score_name"""
            ).fetchall()
        return [dict(row) for row in rows]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _packet_trace_hash(packet: AdmissionPacket) -> str:
    value = packet.evidence.get("trace_sha256")
    if not isinstance(value, str) or not value:
        raise StoreError("admission packet requires evidence.trace_sha256")
    return value


def _validate_event_versions(rows: list[sqlite3.Row]) -> None:
    unknown = [row["schema_version"] for row in rows if row["schema_version"] != 1]
    if unknown:
        raise StoreError(f"unsupported event schema_version: {unknown[0]}")


def _current_config_state(rows: list[sqlite3.Row]) -> tuple[str | None, int | None]:
    current: str | None = None
    event_id: int | None = None
    for row in rows:
        if row["event_type"] in {"CONFIG_PROMOTED", "CONFIG_REVERTED"}:
            current = row["config_hash"]
            event_id = int(row["id"])
        elif row["event_type"] == "CONFIG_INVALIDATED" and row["config_hash"] == current:
            current = None
            event_id = None
    return current, event_id

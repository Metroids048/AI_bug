from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from .domain import (
    AuditEvent,
    CostEntry,
    PlatformResult,
    PlatformResultStatus,
    Program,
    ProgramState,
    _jsonable,
    now_utc,
)

T = TypeVar("T", bound=BaseModel)


SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  program_id TEXT,
  state TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_entities_program ON entities(program_id, entity_type);
CREATE TABLE IF NOT EXISTS cost_entries (
  id TEXT PRIMARY KEY,
  program_id TEXT,
  finding_id TEXT,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  task TEXT NOT NULL,
  input_tokens INTEGER,
  output_tokens INTEGER,
  input_price_per_million REAL,
  output_price_per_million REAL,
  estimated_cost REAL,
  usage_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type, created_at);
"""


class Repository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    @contextmanager
    def transaction(self):
        try:
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def close(self) -> None:
        self.connection.close()

    def save(self, entity_type: str, model: T, program_id: str | None = None, event_type: str = "ENTITY_SAVED") -> T:
        if entity_type == "program":
            existing = self.get("program", model.id, Program)
            if existing and existing.scope_hash() != model.scope_hash():
                model.state = ProgramState.REVIEW_REQUIRED
                model.authorization_hash = None
                model.authorized_at = None
        payload = _jsonable(model)
        state = payload.get("state") if isinstance(payload, dict) else None
        created_at = payload.get("created_at", now_utc().isoformat())
        updated_at = payload.get("updated_at", created_at)
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO entities(entity_type, entity_id, program_id, state, payload_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                   program_id=excluded.program_id, state=excluded.state, payload_json=excluded.payload_json,
                   updated_at=excluded.updated_at""",
                (entity_type, model.id, program_id, state, json.dumps(payload, sort_keys=True), created_at, updated_at),
            )
            self._audit_in_transaction(conn, event_type, entity_type, model.id, {"state": state})
        return model

    def get(self, entity_type: str, entity_id: str, model_type: type[T]) -> T | None:
        row = self.connection.execute(
            "SELECT payload_json FROM entities WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        ).fetchone()
        return model_type.model_validate(json.loads(row["payload_json"])) if row else None

    def list(self, entity_type: str, model_type: type[T], program_id: str | None = None) -> list[T]:
        if program_id is None:
            rows = self.connection.execute(
                "SELECT payload_json FROM entities WHERE entity_type = ? ORDER BY created_at", (entity_type,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT payload_json FROM entities WHERE entity_type = ? AND program_id = ? ORDER BY created_at",
                (entity_type, program_id),
            ).fetchall()
        return [model_type.model_validate(json.loads(row["payload_json"])) for row in rows]

    def get_program(self, program_id: str) -> Program:
        program = self.get("program", program_id, Program)
        if program is None:
            raise KeyError(f"Unknown program: {program_id}")
        return program

    def add_cost(self, entry: CostEntry) -> CostEntry:
        with self.transaction() as conn:
            payload = _jsonable(entry)
            conn.execute(
                """INSERT INTO cost_entries(id, program_id, finding_id, provider, model, task,
                   input_tokens, output_tokens, input_price_per_million, output_price_per_million,
                   estimated_cost, usage_status, created_at, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.id, entry.program_id, entry.finding_id, entry.provider, entry.model, entry.task,
                    entry.input_tokens, entry.output_tokens, entry.input_price_per_million,
                    entry.output_price_per_million, entry.estimated_cost, entry.usage_status,
                    entry.created_at.isoformat(), json.dumps(payload, sort_keys=True),
                ),
            )
            self._audit_in_transaction(conn, "COST_RECORDED", "cost", entry.id, {"task": entry.task})
        return entry

    def cost_summary(self, program_id: str | None = None) -> dict[str, Any]:
        if program_id:
            row = self.connection.execute(
                "SELECT COUNT(*) AS count, SUM(estimated_cost) AS total FROM cost_entries WHERE program_id = ?",
                (program_id,),
            ).fetchone()
        else:
            row = self.connection.execute("SELECT COUNT(*) AS count, SUM(estimated_cost) AS total FROM cost_entries").fetchone()
        unknown = self.connection.execute(
            "SELECT COUNT(*) FROM cost_entries WHERE usage_status = 'UNKNOWN'"
            + (" AND program_id = ?" if program_id else ""),
            (program_id,) if program_id else (),
        ).fetchone()[0]
        return {"entries": row["count"], "known_total": row["total"] or 0.0, "unknown_entries": unknown}

    def roi_summary(self, program_id: str | None = None) -> dict[str, Any]:
        cost = self.cost_summary(program_id)
        if program_id:
            rows = self.connection.execute(
                "SELECT payload_json FROM entities WHERE entity_type = 'platform_result' AND program_id = ?",
                (program_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT payload_json FROM entities WHERE entity_type = 'platform_result'"
            ).fetchall()
        results = [PlatformResult.model_validate(json.loads(row["payload_json"])) for row in rows]
        booked_revenue = sum(
            result.reward for result in results
            if result.status in {PlatformResultStatus.VALID, PlatformResultStatus.PAID}
        )
        paid_revenue = sum(result.reward for result in results if result.status == PlatformResultStatus.PAID)
        model_cost = 0.0
        infrastructure_cost = 0.0
        for row in self.connection.execute(
            "SELECT task, estimated_cost FROM cost_entries WHERE estimated_cost IS NOT NULL"
            + (" AND program_id = ?" if program_id else ""),
            (program_id,) if program_id else (),
        ).fetchall():
            if str(row["task"]).startswith("infra:"):
                infrastructure_cost += row["estimated_cost"] or 0.0
            else:
                model_cost += row["estimated_cost"] or 0.0
        total_cost = model_cost + infrastructure_cost
        net_profit = paid_revenue - total_cost
        return {
            "total_cost": total_cost,
            "model_cost": model_cost,
            "infrastructure_cost": infrastructure_cost,
            "booked_revenue": booked_revenue,
            "paid_revenue": paid_revenue,
            "net_profit": net_profit,
            "roi": (net_profit / total_cost) if total_cost else None,
            "submissions": len(results),
            "valid": sum(result.status in {PlatformResultStatus.VALID, PlatformResultStatus.PAID} for result in results),
            "duplicate": sum(result.status == PlatformResultStatus.DUPLICATE for result in results),
            "informative": sum(result.status == PlatformResultStatus.INFORMATIVE for result in results),
            "invalid": sum(result.status == PlatformResultStatus.INVALID for result in results),
            "unknown_cost_entries": cost["unknown_entries"],
        }

    def audit(self, event_type: str, entity_type: str, entity_id: str, data: dict[str, Any]) -> AuditEvent:
        with self.transaction() as conn:
            event_id = self._audit_in_transaction(conn, event_type, entity_type, entity_id, data)
        return AuditEvent(id=event_id, event_type=event_type, entity_type=entity_type, entity_id=entity_id, data=data)

    def _audit_in_transaction(self, conn: sqlite3.Connection, event_type: str, entity_type: str, entity_id: str, data: dict[str, Any]) -> int:
        cursor = conn.execute(
            "INSERT INTO audit_events(event_type, entity_type, entity_id, data_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, entity_type, entity_id, json.dumps(_jsonable(data), sort_keys=True), now_utc().isoformat()),
        )
        return int(cursor.lastrowid)

    def replay(self) -> list[AuditEvent]:
        rows = self.connection.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        return [
            AuditEvent(
                id=row["id"], event_type=row["event_type"], entity_type=row["entity_type"],
                entity_id=row["entity_id"], data=json.loads(row["data_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def count_recent_actions(self, program_id: str, target: str, window_seconds: int = 60) -> int:
        cutoff = (now_utc().timestamp() - window_seconds)
        rows = self.connection.execute(
            "SELECT data_json, created_at FROM audit_events WHERE event_type = 'ACTION_EXECUTED' "
            "AND entity_id = ? ORDER BY id DESC", (program_id,)
        ).fetchall()
        count = 0
        for row in rows:
            data = json.loads(row["data_json"])
            if data.get("target") == target:
                from datetime import datetime
                if datetime.fromisoformat(row["created_at"]).timestamp() >= cutoff:
                    count += int(data.get("request_count", 1))
        return count

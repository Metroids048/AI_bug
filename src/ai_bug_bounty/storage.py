from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from .benchmark_contracts import BatchIntegrityValidator, canonical_case_outcome
from .domain import (
    AuditEvent,
    CostEntry,
    ExperimentBatch,
    ExperimentBatchStatus,
    ExperimentCaseResult,
    ExperimentRun,
    PlatformResult,
    PlatformResultStatus,
    Program,
    ProgramPolicySnapshot,
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
  experiment_run_id TEXT,
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
        try:
            self.connection.execute("ALTER TABLE cost_entries ADD COLUMN experiment_run_id TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
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
        revoked_program: Program | None = None
        if entity_type == "program":
            existing = self.get("program", model.id, Program)
            if existing and existing.scope_hash() != model.scope_hash():
                model.state = ProgramState.REVIEW_REQUIRED
                model.authorization_hash = None
                model.authorized_at = None
        elif entity_type == "policy_snapshot":
            existing = self.get("policy_snapshot", model.id, ProgramPolicySnapshot)
            if existing and existing.content_hash() != model.content_hash():
                revoked_program = self.get("program", model.program_id, Program)
                model.human_confirmed = False
                if revoked_program:
                    revoked_program.state = ProgramState.REVIEW_REQUIRED
                    revoked_program.authorization_hash = None
                    revoked_program.authorized_at = None
                    revoked_program.updated_at = now_utc()
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
            if revoked_program:
                revoked_payload = _jsonable(revoked_program)
                revoked_state = revoked_payload.get("state")
                revoked_created = revoked_payload.get("created_at", now_utc().isoformat())
                revoked_updated = revoked_payload.get("updated_at", revoked_created)
                conn.execute(
                    """INSERT INTO entities(entity_type, entity_id, program_id, state, payload_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                       program_id=excluded.program_id, state=excluded.state, payload_json=excluded.payload_json,
                       updated_at=excluded.updated_at""",
                    (
                        "program", revoked_program.id, revoked_program.id, revoked_state,
                        json.dumps(revoked_payload, sort_keys=True), revoked_created, revoked_updated,
                    ),
                )
                self._audit_in_transaction(
                    conn, "PROGRAM_AUTHORIZATION_REVOKED", "program", revoked_program.id,
                    {"reason": "POLICY_SNAPSHOT_CHANGED", "state": revoked_state},
                )
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
                   experiment_run_id, input_tokens, output_tokens, input_price_per_million, output_price_per_million,
                   estimated_cost, usage_status, created_at, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.id, entry.program_id, entry.finding_id, entry.provider, entry.model, entry.task,
                    entry.experiment_run_id,
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

    def cost_entries_for_experiment(self, experiment_run_id: str) -> list[CostEntry]:
        rows = self.connection.execute(
            "SELECT payload_json FROM cost_entries WHERE experiment_run_id = ? ORDER BY created_at",
            (experiment_run_id,),
        ).fetchall()
        return [CostEntry.model_validate(json.loads(row["payload_json"])) for row in rows]

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

    def experiment_list(self, program_id: str | None = None) -> list[ExperimentBatch]:
        return self.list("experiment_batch", ExperimentBatch, program_id)

    def experiment_summary(self, program_id: str | None = None, batch_id: str | None = None) -> dict[str, Any]:
        selected_batch: ExperimentBatch | None = None
        if batch_id:
            selected_batch = self.get("experiment_batch", batch_id, ExperimentBatch)
            if selected_batch is None:
                raise ValueError(f"Unknown experiment batch: {batch_id}")
            if program_id and selected_batch.program_id != program_id:
                raise ValueError("batch_id does not belong to program_id")
            program_id = selected_batch.program_id
        elif program_id:
            batches = self.experiment_list(program_id)
            if len(batches) > 1:
                raise ValueError("Multiple experiment batches exist; specify batch_id")
        all_runs = self.list("experiment_run", ExperimentRun)
        all_cases = self.list("experiment_case_result", ExperimentCaseResult)
        if selected_batch:
            run_ids = set(selected_batch.run_ids)
            runs = [item for item in all_runs if item.id in run_ids and item.program_id == selected_batch.program_id]
            cases = [
                item for item in all_cases
                if item.experiment_batch_id == selected_batch.id
                and item.experiment_run_id in run_ids
                and item.program_id == selected_batch.program_id
            ]
            from .experiments import benchmark_version
            integrity = BatchIntegrityValidator(
                selected_batch,
                all_runs,
                all_cases,
                benchmark_version(selected_batch.operation_manifest or None),
            ).validate()
        else:
            runs = [item for item in all_runs if program_id is None or item.program_id == program_id]
            cases = [item for item in all_cases if program_id is None or item.program_id == program_id]
            integrity = BatchIntegrityValidator(None, runs, cases).validate()
        gate_failures: list[str] = list(integrity.failures)
        canonical_outcomes: dict[str, Any] = {}
        for item in cases:
            try:
                canonical_outcomes[item.id] = canonical_case_outcome(item)
            except KeyError:
                gate_failures.append("unknown_scenario")
        tp = sum(outcome.true_positive for outcome in canonical_outcomes.values())
        fp = sum(outcome.false_positive for outcome in canonical_outcomes.values())
        fn = sum(outcome.false_negative for outcome in canonical_outcomes.values())
        contract_failures = sum(not item.contract_valid for item in cases)
        semantic_contract_failures = sum(not item.semantic_contract_valid for item in cases)
        known_cost = sum(item.known_cost for item in runs)
        unknown_cost_entries = sum(item.unknown_cost_entries for item in runs)
        input_tokens = sum(item.input_tokens for item in runs)
        output_tokens = sum(item.output_tokens for item in runs)
        valid_candidates = tp
        scenario_hits: dict[str, int] = {}
        scenario_runs: dict[str, int] = {}
        for item in cases:
            outcome = canonical_outcomes.get(item.id)
            if outcome is None:
                continue
            scenario_runs[item.scenario_key] = scenario_runs.get(item.scenario_key, 0) + 1
            scenario_hits[item.scenario_key] = scenario_hits.get(item.scenario_key, 0) + int(outcome.true_positive)
        if len(runs) < 3 or not cases:
            gate_failures.append("insufficient_rounds")
        if any(item.experiment_batch_id is None for item in runs):
            gate_failures.append("legacy_unbatched")
        if selected_batch and selected_batch.status == ExperimentBatchStatus.FAILED:
            gate_failures.append("batch_failed")
        if sum(item.scope_violations for item in cases) != 0:
            gate_failures.append("scope_violation")
        if fp != 0:
            gate_failures.append("false_positive")
        if contract_failures:
            gate_failures.append("plan_contract_violation")
        truth_paths = {
            item.scenario_key
            for item in cases
            if (outcome := canonical_outcomes.get(item.id)) is not None and outcome.truth_vulnerable
        }
        if any(
            scenario_hits.get(path, 0) < (scenario_runs.get(path, 0) // 2 + 1)
            for path in truth_paths
        ):
            gate_failures.append("true_positive_majority")
        if any(item.reproductions < 2 for item in cases) or any(not item.evidence_complete for item in cases if item.finding_id):
            gate_failures.append("evidence_or_reproduction")
        if unknown_cost_entries != 0:
            gate_failures.append("unknown_cost")
        return {
            "batch_id": selected_batch.id if selected_batch else None,
            "program_id": program_id,
            "provider": selected_batch.provider if selected_batch else (runs[0].provider if runs else None),
            "model": selected_batch.model if selected_batch else (runs[0].model if runs else None),
            "benchmark_version": selected_batch.benchmark_version if selected_batch else None,
            "requested_rounds": selected_batch.requested_rounds if selected_batch else None,
            "status": selected_batch.status.value if selected_batch else None,
            "runs": len(runs),
            "case_runs": len(cases),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "contract_failures": contract_failures,
            "semantic_contract_failures": semantic_contract_failures,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "scope_violations": sum(item.scope_violations for item in cases),
            "reproduction_failures": sum(item.reproductions < 2 for item in cases),
            "evidence_failures": sum(not item.evidence_complete for item in cases if item.finding_id),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "known_cost": known_cost,
            "unknown_cost_entries": unknown_cost_entries,
            "cost_per_true_candidate": known_cost / valid_candidates if valid_candidates else None,
            "gate_passed": not gate_failures,
            "gate_failures": list(dict.fromkeys(gate_failures)),
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

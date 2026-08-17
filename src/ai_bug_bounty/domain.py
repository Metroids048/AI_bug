from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def now_utc() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ProgramState(str, Enum):
    DISCOVERED = "DISCOVERED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    AUTHORIZED = "AUTHORIZED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


class ResearchState(str, Enum):
    HYPOTHESIS = "HYPOTHESIS"
    TESTING = "TESTING"
    OBSERVED = "OBSERVED"
    VALIDATING = "VALIDATING"
    REPRODUCED = "REPRODUCED"
    ADVERSARIAL_REVIEW = "ADVERSARIAL_REVIEW"
    SUBMISSION_READY = "SUBMISSION_READY"
    WAITING_HUMAN = "WAITING_HUMAN"
    SUBMITTED = "SUBMITTED"
    TRIAGED = "TRIAGED"
    INVALID = "INVALID"
    LOW_VALUE = "LOW_VALUE"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    LIKELY_DUPLICATE = "LIKELY_DUPLICATE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ProviderUsage(StrictModel):
    input_tokens: int | None = None
    output_tokens: int | None = None


class ScopeRule(StrictModel):
    asset: str
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET"])
    allowed_actions: list[str] = Field(default_factory=lambda: ["READ"])
    max_requests_per_minute: int = 30


class Rules(StrictModel):
    rate_limit_per_minute: int = 30
    automation_allowed: bool = True
    test_account_rules: str = "Use only researcher-owned test accounts."
    prohibited_actions: list[str] = Field(
        default_factory=lambda: [
            "DOS",
            "STRESS_TEST",
            "CREDENTIAL_STUFFING",
            "DELETE_REAL_DATA",
            "MODIFY_OTHER_USER_DATA",
            "REAL_PAYMENT",
            "FUNDS_TRANSFER",
            "LATERAL_MOVEMENT",
            "PERSISTENCE",
            "MALWARE",
            "MASS_DATA_ACCESS",
        ]
    )


class Program(StrictModel):
    id: str = Field(default_factory=new_id)
    platform: str
    name: str
    program_url: str | None = None
    scopes: list[ScopeRule] = Field(default_factory=list)
    rules: Rules = Field(default_factory=Rules)
    reward_metadata: dict[str, Any] = Field(default_factory=dict)
    state: ProgramState = ProgramState.REVIEW_REQUIRED
    authorization_hash: str | None = None
    authorized_at: datetime | None = None
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)

    def scope_hash(self) -> str:
        payload = {"scopes": self.scopes, "rules": self.rules}
        raw = json.dumps(_jsonable(payload), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


class TargetProfile(StrictModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    asset: str
    category: str
    features: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now_utc)


class Hypothesis(StrictModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    category: str
    asset: str
    feature: str
    expected_security_boundary: str
    hypothesis: str
    reason: str
    validation_plan: str
    required_accounts: list[str] = Field(default_factory=list)
    risk: str = "LOW"
    estimated_cost: float = 1.0
    confidence: float = Field(ge=0, le=1)
    potential_impact: float = Field(default=1.0, ge=0)
    testability: float = Field(default=1.0, ge=0)
    scope_confidence: float = Field(default=1.0, ge=0)
    duplicate_risk: float = Field(default=0.1, gt=0)
    rank_score: float = 0.0
    state: ResearchState = ResearchState.HYPOTHESIS
    created_at: datetime = Field(default_factory=now_utc)


class ActionProposal(StrictModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    hypothesis_id: str
    target: str
    method: str
    action: str
    risk: str
    reason: str
    account_role: str
    request_count: int = 1
    expected_behavior: str
    created_at: datetime = Field(default_factory=now_utc)


class PolicyDecision(StrictModel):
    id: str = Field(default_factory=new_id)
    proposal_id: str
    program_id: str
    decision: Decision
    reason_code: str
    reason: str
    target: str
    method: str
    action: str
    created_at: datetime = Field(default_factory=now_utc)


class Observation(StrictModel):
    id: str = Field(default_factory=new_id)
    hypothesis_id: str
    reproduction_number: int
    expected_behavior: str
    actual_behavior: str
    response_status: int
    response_body: dict[str, Any] = Field(default_factory=dict)
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    account_role: str
    success: bool
    created_at: datetime = Field(default_factory=now_utc)


class Evidence(StrictModel):
    id: str = Field(default_factory=new_id)
    hypothesis_id: str
    observation_id: str
    reproduction_number: int
    request: dict[str, Any]
    response: dict[str, Any]
    expected_behavior: str
    actual_behavior: str
    observed_impact: str
    scope_decision_id: str
    redacted: bool = False
    complete: bool = False
    redaction_status: str = "PENDING"
    created_at: datetime = Field(default_factory=now_utc)


class ValidationResult(StrictModel):
    id: str = Field(default_factory=new_id)
    hypothesis_id: str
    observation_id: str
    evidence_id: str
    reproduction_number: int
    passed: bool
    reason: str
    created_at: datetime = Field(default_factory=now_utc)


class JudgeResult(StrictModel):
    id: str = Field(default_factory=new_id)
    finding_id: str
    passed: bool
    scope_passed: bool
    reproducibility_passed: bool
    evidence_passed: bool
    boundary_passed: bool
    impact_passed: bool
    skeptic_passed: bool
    report_quality_passed: bool
    counterarguments: list[str] = Field(default_factory=list)
    reason: str
    created_at: datetime = Field(default_factory=now_utc)


class Finding(StrictModel):
    id: str = Field(default_factory=new_id)
    program_id: str
    hypothesis_id: str
    asset: str
    category: str
    title: str
    security_boundary: str
    expected_behavior: str
    actual_behavior: str
    observed_impact: str
    potential_impact: str
    observation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    validation_result_ids: list[str] = Field(default_factory=list)
    judge_result_id: str | None = None
    state: ResearchState = ResearchState.TESTING
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)


class ReportDraft(StrictModel):
    id: str = Field(default_factory=new_id)
    finding_id: str
    title: str
    markdown: str
    state: ResearchState = ResearchState.SUBMISSION_READY
    created_at: datetime = Field(default_factory=now_utc)


class CostEntry(StrictModel):
    id: str = Field(default_factory=new_id)
    provider: str
    model: str
    task: str
    program_id: str | None = None
    finding_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None
    estimated_cost: float | None = None
    usage_status: str = "UNKNOWN"
    created_at: datetime = Field(default_factory=now_utc)


class AuditEvent(StrictModel):
    id: int | None = None
    event_type: str
    entity_type: str
    entity_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now_utc)


class HypothesisBatch(StrictModel):
    hypotheses: list[Hypothesis] = Field(min_length=5, max_length=20)


class SkepticResult(StrictModel):
    supports_finding: bool
    counterarguments: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Enum):
        return value.value
    return value

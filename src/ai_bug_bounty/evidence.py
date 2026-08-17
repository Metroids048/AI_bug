from __future__ import annotations

import json
import re
from typing import Any

from .domain import Evidence, Observation, PolicyDecision
from .storage import Repository

SENSITIVE_KEY = re.compile(r"(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|session|email|phone|ssn)", re.I)
BEARER = re.compile(r"(Bearer\s+)[^\s]+", re.I)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{7,}\d)(?!\d)")
TOKEN = re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{10,}\b|\beyJ[A-Za-z0-9_-]{20,}\b")


class RedactionError(ValueError):
    pass


def redact(value: Any, key: str | None = None) -> Any:
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = BEARER.sub(r"\1[REDACTED]", value)
        value = EMAIL.sub("[REDACTED_EMAIL]", value)
        value = PHONE.sub("[REDACTED_PHONE]", value)
        value = TOKEN.sub("[REDACTED_TOKEN]", value)
        return value
    return value


def _contains_secret(serialized: str) -> bool:
    return bool(
        BEARER.search(serialized)
        or EMAIL.search(serialized)
        or PHONE.search(serialized)
        or TOKEN.search(serialized)
        or re.search(r"(?i)(api[_-]?key|password|secret|session_token)\"\s*:\s*\"(?!\[REDACTED)", serialized)
    )


class EvidenceStore:
    def __init__(self, repository: Repository):
        self.repository = repository

    def persist(
        self,
        observation: Observation,
        decision: PolicyDecision,
        observed_impact: str,
    ) -> Evidence:
        request = redact(observation.request_metadata)
        response = redact(observation.response_body)
        serialized = json.dumps({"request": request, "response": response}, sort_keys=True)
        if _contains_secret(serialized):
            raise RedactionError("Evidence still contains a sensitive value after redaction.")
        complete = bool(
            observation.expected_behavior
            and observation.actual_behavior
            and observed_impact
            and decision.decision.value == "ALLOW"
            and observation.response_status >= 100
        )
        evidence = Evidence(
            hypothesis_id=observation.hypothesis_id,
            observation_id=observation.id,
            reproduction_number=observation.reproduction_number,
            request=request,
            response=response,
            expected_behavior=observation.expected_behavior,
            actual_behavior=observation.actual_behavior,
            observed_impact=observed_impact,
            scope_decision_id=decision.id,
            redacted=True,
            complete=complete,
            redaction_status="REDACTED",
        )
        self.repository.save("evidence", evidence)
        return evidence

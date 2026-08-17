from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .domain import Evidence, Observation, PolicyDecision
from .storage import Repository

SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|session|phone|ssn)", re.I
)
BEARER = re.compile(r"(Bearer\s+)[^\s]+", re.I)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{7,}\d)(?!\d)")
TOKEN = re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{10,}\b|\beyJ[A-Za-z0-9_-]{20,}\b")


class RedactionError(ValueError):
    pass


def _email_label(value: str, identity_labels: dict[str, str]) -> str:
    local = value.split("@", 1)[0].lower()
    label = identity_labels.get(local)
    if label is None:
        digest = hashlib.sha256(local.encode()).hexdigest()[:8].upper()
        label = f"ACCOUNT_{digest}"
    return f"[{label}_EMAIL]"


def redact(value: Any, key: str | None = None, identity_labels: dict[str, str] | None = None) -> Any:
    identity_labels = identity_labels or {}
    if key and key.lower().endswith("email") and isinstance(value, str) and EMAIL.fullmatch(value):
        return _email_label(value, identity_labels)
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k), identity_labels) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, identity_labels=identity_labels) for item in value]
    if isinstance(value, str):
        value = BEARER.sub(r"\1[REDACTED]", value)
        value = EMAIL.sub(lambda match: _email_label(match.group(0), identity_labels), value)
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
        or re.search(r'(?i)(api[_-]?key|password|secret|session_token)"\s*:\s*"(?!\[REDACTED)', serialized)
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
        identity_labels = {
            "alice": "ACCOUNT_A",
            "bob": "ACCOUNT_B",
            "account_a": "ACCOUNT_A",
            "account_b": "ACCOUNT_B",
        }
        request = redact(observation.request_metadata, identity_labels=identity_labels)
        response = redact(observation.response_body, identity_labels=identity_labels)
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
            identity_labels=identity_labels,
        )
        self.repository.save("evidence", evidence)
        return evidence

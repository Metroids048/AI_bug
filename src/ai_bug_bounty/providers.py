from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from .domain import Hypothesis, HypothesisBatch, ProviderUsage, SkepticResult

T = TypeVar("T", bound=BaseModel)


class ProviderDisabled(RuntimeError):
    pass


@dataclass
class ProviderResult:
    data: BaseModel
    provider: str
    model: str
    usage: ProviderUsage


class Provider:
    name = "provider"
    model = "unknown"

    def plan(self, program_id: str, asset: str) -> ProviderResult:
        raise NotImplementedError

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        raise NotImplementedError


class DeterministicProvider(Provider):
    name = "deterministic"
    model = "offline-rules-v1"

    def plan(self, program_id: str, asset: str) -> ProviderResult:
        common = {
            "program_id": program_id,
            "asset": asset,
            "category": "authorization",
            "required_accounts": ["account_a", "account_b"],
            "risk": "LOW",
            "scope_confidence": 1.0,
        }
        candidates = [
            Hypothesis(
                **common, feature="GET /api/documents/{id}",
                expected_security_boundary="Account B must not read Account A private document.",
                hypothesis="The document identifier may be accepted without an ownership check.",
                reason="Object identifiers are read through an authenticated API path.",
                validation_plan="Use two researcher-owned accounts and request Account A's document as Account B.",
                confidence=0.92, potential_impact=8, testability=1.0, estimated_cost=1.0, duplicate_risk=0.2,
            ),
            Hypothesis(
                **common, feature="GET /api/profile/{user_id}",
                expected_security_boundary="Account B must not read Account A private profile.",
                hypothesis="The profile endpoint may return another user's private profile.",
                reason="The endpoint accepts an arbitrary user identifier.",
                validation_plan="Request Account A profile with Account B's clean session.",
                confidence=0.65, potential_impact=5, testability=1.0, estimated_cost=1.0, duplicate_risk=0.3,
            ),
            Hypothesis(
                **common, feature="GET /api/documents/missing",
                expected_security_boundary="Unknown document identifiers must return 404.",
                hypothesis="A missing document may disclose internal information.",
                reason="Error paths can expose implementation details.",
                validation_plan="Request a non-existent document and inspect only the response metadata.",
                confidence=0.2, potential_impact=2, testability=1.0, estimated_cost=1.0, duplicate_risk=0.6,
            ),
            Hypothesis(
                **common, feature="GET /api/documents/{own_id}",
                expected_security_boundary="An owner may read their own private document.",
                hypothesis="The normal owner path may be unavailable or inconsistent.",
                reason="A positive control distinguishes an authorization issue from a broken feature.",
                validation_plan="Request Account A's document as Account A.",
                confidence=0.3, potential_impact=1, testability=1.0, estimated_cost=1.0, duplicate_risk=0.7,
            ),
            Hypothesis(
                **common, feature="POST /api/documents/{id}",
                expected_security_boundary="State-changing actions require explicit program permission.",
                hypothesis="A write method may be reachable through a read-only scope.",
                reason="Method confusion is a common policy failure mode.",
                validation_plan="Do not execute; verify the policy denies the method before any request.",
                confidence=0.3, potential_impact=4, testability=0.8, estimated_cost=1.0, duplicate_risk=0.5,
            ),
        ]
        return ProviderResult(HypothesisBatch(hypotheses=candidates), self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0))

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        supports = bool(context.get("cross_account_private_data"))
        result = SkepticResult(
            supports_finding=supports,
            counterarguments=[] if supports else ["The observed response does not cross an account boundary."],
            confidence=0.95 if supports else 0.98,
        )
        return ProviderResult(result, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0))


class OpenAICompatibleProvider(Provider):
    name = "openai-compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        network_enabled: bool = False,
        input_price_per_million: float | None = None,
        output_price_per_million: float | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.network_enabled = network_enabled
        self.input_price_per_million = input_price_per_million
        self.output_price_per_million = output_price_per_million

    def _call(self, task: str, context: dict[str, Any], schema: type[T]) -> ProviderResult:
        if not self.network_enabled:
            raise ProviderDisabled("Model network is disabled; enable it explicitly for a smoke test.")
        prompt = (
            "Return JSON only matching the requested schema. Do not invent observations. "
            f"Task: {task}\nContext: {json.dumps(context, sort_keys=True)}"
        )
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        usage = payload.get("usage", {})
        result = schema.model_validate_json(content)
        return ProviderResult(
            result,
            self.name,
            self.model,
            ProviderUsage(usage.get("prompt_tokens"), usage.get("completion_tokens")),
        )

    def plan(self, program_id: str, asset: str) -> ProviderResult:
        return self._call("planner", {"program_id": program_id, "asset": asset}, HypothesisBatch)

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        return self._call("skeptic", context, SkepticResult)

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from .domain import (
    Hypothesis,
    HypothesisBatch,
    ImpactReviewResult,
    ProviderUsage,
    SkepticResult,
    ValidationPlan,
    ValidationStep,
)

T = TypeVar("T", bound=BaseModel)


class ProviderDisabled(RuntimeError):
    pass


@dataclass
class ProviderResult:
    data: BaseModel
    provider: str
    model: str
    usage: ProviderUsage
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None


class Provider:
    name = "provider"
    model = "unknown"
    input_price_per_million: float | None = 0.0
    output_price_per_million: float | None = 0.0

    def plan(self, program_id: str, asset: str, context: dict[str, Any] | None = None) -> ProviderResult:
        raise NotImplementedError

    def validation_plan(self, hypothesis: Hypothesis, context: dict[str, Any]) -> ProviderResult:
        raise NotImplementedError

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        raise NotImplementedError

    def impact(self, context: dict[str, Any]) -> ProviderResult:
        raise NotImplementedError


class DeterministicProvider(Provider):
    """Legacy fixture provider retained for unit tests; never the production default."""

    name = "deterministic-fixture"
    model = "offline-rules-v1"

    def plan(self, program_id: str, asset: str, context: dict[str, Any] | None = None) -> ProviderResult:
        common = {
            "program_id": program_id,
            "asset": asset,
            "category": "authorization",
            "required_accounts": ["account_a", "account_b"],
            "risk": "LOW",
            "scope_confidence": 1.0,
            "source": "fixture-only",
        }
        candidates = [
            Hypothesis(
                **common, feature="GET /api/documents/{id}",
                expected_security_boundary="Account B must not read Account A private document.",
                hypothesis="The document identifier may be accepted without an ownership check.",
                reason="Object identifiers are read through an authenticated API path.",
                validation_plan="Use two researcher-owned accounts and request the same resource as Account A and B.",
                confidence=0.92, potential_impact=8, testability=1.0, estimated_cost=1.0, duplicate_risk=0.2,
            ),
            Hypothesis(
                **common, feature="GET /api/profile/{user_id}",
                expected_security_boundary="Account B must not read Account A private profile.",
                hypothesis="The profile endpoint may return another user's private profile.",
                reason="The endpoint accepts an arbitrary user identifier.",
                validation_plan="Request the same profile with Account A and Account B clean sessions.",
                confidence=0.65, potential_impact=5, testability=1.0, estimated_cost=1.0, duplicate_risk=0.3,
            ),
            Hypothesis(
                **common, feature="GET /api/documents/missing",
                expected_security_boundary="Unknown document identifiers must return 404.",
                hypothesis="A missing document may disclose internal information.",
                reason="Error paths can expose implementation details.",
                validation_plan="Request a non-existent document and inspect only response metadata.",
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
                validation_plan="Verify policy denies the method before any request.",
                confidence=0.3, potential_impact=4, testability=0.8, estimated_cost=1.0, duplicate_risk=0.5,
            ),
        ]
        return ProviderResult(
            HypothesisBatch(hypotheses=candidates), self.name, self.model,
            ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0,
        )

    def validation_plan(self, hypothesis: Hypothesis, context: dict[str, Any]) -> ProviderResult:
        path = "/api/profile/alice" if "profile" in hypothesis.feature else "/api/documents/doc-a"
        steps = [
            ValidationStep(
                phase="CONTROL", target=f"lab://idor{path}", method="GET", action="READ",
                account_role="account_a", resource_key="resource-a",
                expected_behavior="Account A can access its own resource.", expected_status=200,
            ),
            ValidationStep(
                phase="TEST", target=f"lab://idor{path}", method="GET", action="READ_OTHER_TEST_ACCOUNT_DATA",
                account_role="account_b", resource_key="resource-a",
                expected_behavior="Account B must be denied.", expected_status=403,
            ),
        ]
        return ProviderResult(
            ValidationPlan(hypothesis_id=hypothesis.id, objective=hypothesis.hypothesis, steps=steps),
            self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0,
        )

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        supports = _evidence_supports_boundary(context.get("evidence", []))
        result = SkepticResult(
            supports_finding=supports,
            counterarguments=[] if supports else ["The observed response does not cross an account boundary."],
            confidence=0.95 if supports else 0.98,
        )
        return ProviderResult(result, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0)

    def impact(self, context: dict[str, Any]) -> ProviderResult:
        observed = context.get("observed_impact", "")
        result = ImpactReviewResult(
            observed_impact=observed,
            potential_impact="Cross-account access to private resources within the tested boundary.",
            passed=bool(observed),
            confidence=0.9,
        )
        return ProviderResult(result, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0)


class BlindBenchmarkProvider(Provider):
    """Offline model surrogate that sees only public benchmark metadata, never the oracle."""

    name = "blind-benchmark"
    model = "offline-blind-v1"

    def plan(self, program_id: str, asset: str, context: dict[str, Any] | None = None) -> ProviderResult:
        context = context or {}
        operations = context.get("operations", [])
        candidates: list[Hypothesis] = []
        for operation in operations:
            path = operation["path"]
            method = operation["method"].upper()
            description = operation.get("description", "")
            kind = operation.get("kind", "authorization")
            if kind == "authorization":
                boundary = "A resource owner may access its resource; another account should be denied."
                statement = "The endpoint may accept a resource identifier without enforcing ownership."
                accounts = ["account_a", "account_b"]
            elif kind == "information":
                boundary = "Authenticated users should not receive internal configuration or private fields."
                statement = "The response may disclose fields outside the caller's permitted information boundary."
                accounts = ["account_a", "account_b"]
            else:
                boundary = "A one-time business operation should not be repeatable after its state is consumed."
                statement = "The endpoint may allow an invalid state transition or repeated benefit."
                accounts = ["account_a"]
            candidates.append(Hypothesis(
                program_id=program_id,
                target_profile_id=context.get("target_profile_id"),
                asset=asset,
                category=kind,
                feature=f"{method} {path}",
                expected_security_boundary=boundary,
                hypothesis=statement,
                reason=f"Public operation description: {description}",
                validation_plan="Compare a permitted control with a boundary-breaking test using only supplied test accounts.",
                required_accounts=accounts,
                risk="LOW",
                estimated_cost=1.0,
                confidence=0.7,
                potential_impact=6 if kind != "information" else 5,
                testability=1.0,
                scope_confidence=1.0,
                duplicate_risk=0.5,
                source="blind-benchmark",
            ))
        while len(candidates) < 5:
            candidates.append(Hypothesis(
                program_id=program_id, target_profile_id=context.get("target_profile_id"), asset=asset,
                category="authorization", feature="generic negative control",
                expected_security_boundary="A denied request must not return protected data.",
                hypothesis="A safe control may unexpectedly cross a security boundary.",
                reason="Negative control for false-positive measurement.",
                validation_plan="Execute the supplied safe control only.", required_accounts=["account_a", "account_b"],
                risk="LOW", estimated_cost=1.0, confidence=0.2, potential_impact=1,
                testability=1.0, scope_confidence=1.0, duplicate_risk=0.9, source="blind-benchmark",
            ))
        batch = HypothesisBatch(hypotheses=candidates[:20])
        return ProviderResult(batch, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0)

    def validation_plan(self, hypothesis: Hypothesis, context: dict[str, Any]) -> ProviderResult:
        operation = next(item for item in context.get("operations", []) if item["path"] in hypothesis.feature)
        target_path = _benchmark_target_path(operation["path"])
        is_business = operation.get("kind") == "business"
        account = "account_a"
        test_account = "account_a" if is_business else "account_b"
        steps = [
            ValidationStep(
                phase="CONTROL", target=f"lab://benchmark{target_path}", method=operation["method"],
                action="WRITE_TEST_DATA" if is_business else "READ",
                account_role=account, resource_key=operation["path"],
                expected_behavior="The permitted control should succeed without exposing unrelated data.",
                expected_status=200,
                request_payload={"code": "WELCOME"} if is_business else None,
            ),
            ValidationStep(
                phase="TEST", target=f"lab://benchmark{target_path}", method=operation["method"],
                action="WRITE_TEST_DATA" if is_business else "READ_OTHER_TEST_ACCOUNT_DATA",
                account_role=test_account, resource_key=operation["path"],
                expected_behavior="The boundary-breaking test should be denied or return no protected fields.",
                expected_status=409 if is_business else 403,
                request_payload={"code": "WELCOME"} if is_business else None,
            ),
        ]
        return ProviderResult(
            ValidationPlan(hypothesis_id=hypothesis.id, objective=hypothesis.hypothesis, steps=steps),
            self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0,
        )

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        broken = _evidence_supports_boundary(context.get("evidence", []))
        result = SkepticResult(
            supports_finding=broken,
            counterarguments=[] if broken else ["The control and test observations do not demonstrate unauthorized behavior."],
            confidence=0.9 if broken else 0.95,
        )
        return ProviderResult(result, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0)

    def impact(self, context: dict[str, Any]) -> ProviderResult:
        observed = context.get("observed_impact", "")
        result = ImpactReviewResult(
            observed_impact=observed,
            potential_impact="Only the observed local benchmark impact is considered; no live impact is inferred.",
            passed=bool(observed), confidence=0.9,
        )
        return ProviderResult(result, self.name, self.model, ProviderUsage(input_tokens=0, output_tokens=0), 0.0, 0.0)


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
        if not self.api_key:
            raise ProviderDisabled("Model API key is missing; set ABB_LLM_API_KEY explicitly.")
        prompt = (
            "Return JSON only matching the requested schema. Do not invent observations or scope. "
            f"Task: {task}\nContext: {json.dumps(context, sort_keys=True)}"
        )
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]},
            timeout=30,
        )
        # Mock transports may not attach a Request object; status-code gating
        # preserves the HTTP error behavior without requiring that metadata.
        if response.status_code >= 400:
            response.raise_for_status()
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        if content.strip().startswith("```"):
            content = content.strip().strip("`")
            if content.startswith("json"):
                content = content[4:]
        usage = payload.get("usage", {})
        result = schema.model_validate_json(content)
        return ProviderResult(
            result, self.name, self.model,
            ProviderUsage(input_tokens=usage.get("prompt_tokens"), output_tokens=usage.get("completion_tokens")),
            self.input_price_per_million, self.output_price_per_million,
        )

    def plan(self, program_id: str, asset: str, context: dict[str, Any] | None = None) -> ProviderResult:
        return self._call("planner", {"program_id": program_id, "asset": asset, **(context or {})}, HypothesisBatch)

    def validation_plan(self, hypothesis: Hypothesis, context: dict[str, Any]) -> ProviderResult:
        return self._call("validator-planner", {"hypothesis": hypothesis.model_dump(mode="json"), **context}, ValidationPlan)

    def skeptic(self, context: dict[str, Any]) -> ProviderResult:
        return self._call("skeptic", context, SkepticResult)

    def impact(self, context: dict[str, Any]) -> ProviderResult:
        return self._call("impact-reviewer", context, ImpactReviewResult)


def provider_factory(name: str | None = None) -> Provider:
    provider_name = (name or os.getenv("ABB_LLM_PROVIDER", "openai-compatible")).lower()
    if provider_name in {"blind", "benchmark", "blind-benchmark"}:
        return BlindBenchmarkProvider()
    if provider_name in {"deterministic", "fixture"}:
        return DeterministicProvider()
    if provider_name in {"openai", "openai-compatible", "deepseek", "cc-switch"}:
        base_url = os.getenv("ABB_LLM_BASE_URL", "http://127.0.0.1:18789/v1")
        model = os.getenv("ABB_LLM_MODEL", "deepseek-chat")
        api_key = os.getenv("ABB_LLM_API_KEY", "")
        network_enabled = os.getenv("ABB_LLM_NETWORK_ENABLED", "false").lower() == "true"
        return OpenAICompatibleProvider(
            base_url=base_url,
            model=model,
            api_key=api_key,
            network_enabled=network_enabled,
            input_price_per_million=_optional_float(os.getenv("ABB_LLM_INPUT_PRICE_PER_MILLION")),
            output_price_per_million=_optional_float(os.getenv("ABB_LLM_OUTPUT_PRICE_PER_MILLION")),
        )
    raise ValueError(f"Unknown provider: {name}")


def _optional_float(value: str | None) -> float | None:
    return float(value) if value not in {None, ""} else None


def _benchmark_target_path(path: str) -> str:
    replacements = {
        "/api/documents/{id}": "/api/documents/doc-a",
        "/api/secure-documents/{id}": "/api/secure-documents/doc-a",
        "/api/public-profiles/{id}": "/api/public-profiles/alice",
        "/api/shared-documents/{id}": "/api/shared-documents/shared-doc",
        "/api/resource-metadata/{id}": "/api/resource-metadata/item-1",
    }
    return replacements.get(path, path)


def _evidence_supports_boundary(evidence: list[dict[str, Any]]) -> bool:
    for item in evidence:
        if item.get("phase") != "TEST":
            continue
        body = item.get("response", {})
        if _contains_boundary_marker(body):
            return True
    return False


def _contains_boundary_marker(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if any(marker in normalized for marker in ("private", "secret", "token", "email")):
                return True
            if normalized == "redeemed" and item is True:
                return True
            if _contains_boundary_marker(item):
                return True
    if isinstance(value, list):
        return any(_contains_boundary_marker(item) for item in value)
    return False

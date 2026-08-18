from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from .domain import (
    BenchmarkHypothesis,
    BenchmarkHypothesisBatch,
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


class ProviderCallError(RuntimeError):
    """Sanitized, deterministic failure contract for one provider call."""

    def __init__(
        self,
        *,
        stage: str,
        reason_code: str,
        http_status: int | None = None,
        retry_after: str | None = None,
        attempts: int = 1,
    ):
        self.stage = stage
        self.reason_code = reason_code
        self.http_status = http_status
        self.retry_after = retry_after
        self.attempts = attempts
        status = f" status={http_status}" if http_status is not None else ""
        super().__init__(f"{reason_code} at {stage}{status}")


def _classify_provider_error(stage: str, exc: Exception, *, attempts: int = 1) -> ProviderCallError:
    if isinstance(exc, httpx.TimeoutException):
        return ProviderCallError(stage=stage, reason_code="PROVIDER_TIMEOUT", attempts=attempts)
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        status = response.status_code if response is not None else None
        retry_after = response.headers.get("Retry-After") if response is not None else None
        if status in {401, 403}:
            reason_code = "PROVIDER_AUTH"
        elif status == 429:
            reason_code = "PROVIDER_RATE_LIMIT"
        elif status is not None and 400 <= status < 500:
            reason_code = "PROVIDER_REQUEST_REJECTED"
        elif status is not None and 500 <= status < 600:
            reason_code = "PROVIDER_UPSTREAM"
        else:
            reason_code = "PROVIDER_HTTP_ERROR"
        return ProviderCallError(
            stage=stage,
            reason_code=reason_code,
            http_status=status,
            retry_after=retry_after,
            attempts=attempts,
        )
    if isinstance(exc, httpx.RequestError):
        return ProviderCallError(stage=stage, reason_code="PROVIDER_NETWORK", attempts=attempts)
    raise exc


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
        if asset == "lab://benchmark" and context and context.get("operations"):
            candidates = [
                BenchmarkHypothesis(
                    program_id=program_id,
                    target_profile_id=context.get("target_profile_id"),
                    asset=asset,
                    category="authorization",
                    feature=f"{operation['method']} {operation['path']}",
                    operation_method=operation["method"],
                    operation_path=operation["path"],
                    expected_security_boundary="The documented operation should respect its stated security boundary.",
                    hypothesis="The operation may behave differently from its documented security boundary.",
                    reason=f"Public operation description: {operation.get('description', '')}",
                    validation_plan="Compare a control and test response.",
                    required_accounts=["account_a", "account_b"],
                    confidence=0.5,
                    potential_impact=1,
                    testability=1,
                    scope_confidence=1,
                    duplicate_risk=0.9,
                    source="deterministic-fixture",
                )
                for operation in context["operations"]
            ]
            return ProviderResult(
                BenchmarkHypothesisBatch(hypotheses=candidates),
                self.name,
                self.model,
                ProviderUsage(input_tokens=0, output_tokens=0),
                0.0,
                0.0,
            )
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
                operation_method="GET", operation_path="/api/documents/{id}",
                expected_security_boundary="Account B must not read Account A private document.",
                hypothesis="The document identifier may be accepted without an ownership check.",
                reason="Object identifiers are read through an authenticated API path.",
                validation_plan="Use two researcher-owned accounts and request the same resource as Account A and B.",
                confidence=0.92, potential_impact=8, testability=1.0, estimated_cost=1.0, duplicate_risk=0.2,
            ),
            Hypothesis(
                **common, feature="GET /api/profile/{user_id}",
                operation_method="GET", operation_path="/api/profile/{user_id}",
                expected_security_boundary="Account B must not read Account A private profile.",
                hypothesis="The profile endpoint may return another user's private profile.",
                reason="The endpoint accepts an arbitrary user identifier.",
                validation_plan="Request the same profile with Account A and Account B clean sessions.",
                confidence=0.65, potential_impact=5, testability=1.0, estimated_cost=1.0, duplicate_risk=0.3,
            ),
            Hypothesis(
                **common, feature="GET /api/documents/missing",
                operation_method="GET", operation_path="/api/documents/{id}",
                expected_security_boundary="Unknown document identifiers must return 404.",
                hypothesis="A missing document may disclose internal information.",
                reason="Error paths can expose implementation details.",
                validation_plan="Request a non-existent document and inspect only response metadata.",
                confidence=0.2, potential_impact=2, testability=1.0, estimated_cost=1.0, duplicate_risk=0.6,
            ),
            Hypothesis(
                **common, feature="GET /api/documents/{own_id}",
                operation_method="GET", operation_path="/api/documents/{id}",
                expected_security_boundary="An owner may read their own private document.",
                hypothesis="The normal owner path may be unavailable or inconsistent.",
                reason="A positive control distinguishes an authorization issue from a broken feature.",
                validation_plan="Request Account A's document as Account A.",
                confidence=0.3, potential_impact=1, testability=1.0, estimated_cost=1.0, duplicate_risk=0.7,
            ),
            Hypothesis(
                **common, feature="POST /api/documents/{id}",
                operation_method="POST", operation_path="/api/documents/{id}",
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
            kind = _benchmark_kind(path)
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
            candidates.append(BenchmarkHypothesis(
                program_id=program_id,
                target_profile_id=context.get("target_profile_id"),
                asset=asset,
                category=kind,
                feature=f"{method} {path}",
                operation_method=method,
                operation_path=path,
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
            candidates.append(BenchmarkHypothesis(
                program_id=program_id, target_profile_id=context.get("target_profile_id"), asset=asset,
                category="authorization", feature="generic negative control", operation_method="GET", operation_path="/api/items/{id}",
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
        feature_path = hypothesis.operation_path
        if not feature_path:
            raise ValueError("Benchmark hypothesis is missing operation_path")
        operation = next(item for item in context.get("operations", []) if item["path"] == feature_path)
        target_path = _benchmark_target_path(operation["path"])
        is_business = _benchmark_kind(operation["path"]) == "business"
        account = "account_a"
        test_account = "account_a" if is_business else "account_b"
        steps = [
            ValidationStep(
                phase="CONTROL", target=f"lab://benchmark{target_path}", method=operation["method"],
                action="WRITE_TEST_DATA" if is_business else "READ",
                account_role=account, resource_key=operation["path"],
                expected_behavior="The permitted control should succeed without exposing unrelated data.",
                expected_status=200,
                request_payload={"code": context.get("test_inputs", {}).get("promotion_code", "WELCOME")} if is_business else None,
            ),
            ValidationStep(
                phase="TEST", target=f"lab://benchmark{target_path}", method=operation["method"],
                action="WRITE_TEST_DATA" if is_business else "READ_OTHER_TEST_ACCOUNT_DATA",
                account_role=test_account, resource_key=operation["path"],
                expected_behavior="The boundary-breaking test should be denied or return no protected fields.",
                expected_status=409 if is_business else 403,
                request_payload={"code": context.get("test_inputs", {}).get("promotion_code", "WELCOME")} if is_business else None,
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
        timeout_seconds: float = 30.0,
        transient_max_retries: int = 2,
        transient_backoff_seconds: float = 2.0,
    ):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
        if not isinstance(transient_max_retries, int) or isinstance(transient_max_retries, bool) or transient_max_retries < 0:
            raise ValueError("transient_max_retries must be a non-negative integer")
        if not math.isfinite(transient_backoff_seconds) or transient_backoff_seconds < 0:
            raise ValueError("transient_backoff_seconds must be finite and non-negative")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.network_enabled = network_enabled
        self.input_price_per_million = input_price_per_million
        self.output_price_per_million = output_price_per_million
        self.timeout_seconds = timeout_seconds
        self.transient_max_retries = transient_max_retries
        self.transient_backoff_seconds = transient_backoff_seconds

    def _call(self, task: str, context: dict[str, Any], schema: type[T]) -> ProviderResult:
        if not self.network_enabled:
            raise ProviderDisabled("Model network is disabled; enable it explicitly for a smoke test.")
        if not self.api_key:
            raise ProviderDisabled("Model API key is missing; set ABB_LLM_API_KEY explicitly.")
        schema_definition = schema.model_json_schema()
        if task == "validator-planner" and context.get("hypothesis", {}).get("asset") == "lab://benchmark":
            schema_definition = _without_benchmark_oracle_fields(schema_definition)
        schema_json = json.dumps(schema_definition, sort_keys=True)
        prompt = self._prompt(task, context, schema_json)
        try:
            _, content, usage = self._request(task, prompt, schema, schema_definition)
        except ProviderCallError:
            raise
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
            raise _classify_provider_error(task, exc) from exc
        try:
            result = schema.model_validate_json(content)
        except Exception as first_error:
            repair_prompt = self._prompt(
                task,
                context,
                schema_json,
                repair=f"The previous JSON failed schema validation: {str(first_error)[:1000]}",
                previous_response=content,
            )
            try:
                _, repair_content, repair_usage = self._request(task, repair_prompt, schema, schema_definition)
            except ProviderCallError:
                raise
            except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
                raise _classify_provider_error(task, exc) from exc
            usage = _merge_usage(usage, repair_usage)
            try:
                result = schema.model_validate_json(repair_content)
            except Exception as second_error:
                raise ValueError(f"Provider response failed schema validation after one repair: {second_error}") from second_error
        return ProviderResult(
            result, self.name, self.model,
            ProviderUsage(input_tokens=usage.get("prompt_tokens"), output_tokens=usage.get("completion_tokens")),
            self.input_price_per_million, self.output_price_per_million,
        )

    def _prompt(
        self,
        task: str,
        context: dict[str, Any],
        schema_json: str,
        repair: str | None = None,
        previous_response: str | None = None,
    ) -> str:
        prompt_context = dict(context)
        coverage_repair = prompt_context.pop("_benchmark_coverage_repair", None)
        lines = [
            "Return exactly one JSON object and no Markdown.",
            "Use only facts from Context; do not invent scope, accounts, observations, or business rules.",
            f"Task: {task}",
            f"JSON Schema: {schema_json}",
        ]
        if task == "planner" and prompt_context.get("asset") == "lab://benchmark":
            lines.extend([
                "For the benchmark, return exactly one hypothesis for every public operation in Context.operations.",
                "Preserve each operation's method and path exactly.",
                "Do not omit, duplicate, merge, invent, rank away, or replace operations.",
                "This requirement describes experiment coverage only.",
                "It does not imply that any operation is vulnerable.",
            ])
        lines.append(f"Context: {json.dumps(prompt_context, sort_keys=True)}")
        if coverage_repair:
            lines.extend([
                "Structural coverage repair diagnostics (operation identities only):",
                f"Missing operation identities: {json.dumps(coverage_repair.get('missing', []), sort_keys=True)}",
                f"Duplicate operation identities: {json.dumps(coverage_repair.get('duplicate', []), sort_keys=True)}",
                f"Unknown operation identities: {json.dumps(coverage_repair.get('unknown', []), sort_keys=True)}",
            ])
        if repair:
            lines.extend([repair, f"Previous response to repair: {previous_response or ''}"])
        return "\n".join(lines)

    def _request(
        self,
        stage: str,
        prompt: str,
        schema: type[T],
        schema_definition: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
        request_json: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        }
        if os.getenv("ABB_LLM_STRUCTURED_OUTPUT", "false").lower() == "true":
            request_json["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema.__name__, "strict": True, "schema": schema_definition or schema.model_json_schema()},
            }
        attempts = 0
        while True:
            attempts += 1
            try:
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=request_json,
                    timeout=self.timeout_seconds,
                )
                # Mock transports may not attach a Request object; status-code gating
                # preserves the HTTP error behavior without requiring that metadata.
                if response.status_code >= 400:
                    try:
                        request = response.request
                    except RuntimeError:
                        request = httpx.Request("POST", f"{self.base_url}/chat/completions")
                    raise httpx.HTTPStatusError("provider returned an HTTP error", request=request, response=response)
                payload = response.json()
                content = _clean_json_content(payload["choices"][0]["message"]["content"])
                return payload, content, payload.get("usage", {})
            except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as exc:
                status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None else None
                transient = status in {502, 503, 504}
                if transient and attempts <= self.transient_max_retries:
                    delay = self.transient_backoff_seconds * (2 ** (attempts - 1))
                    if delay:
                        time.sleep(delay)
                    continue
                raise _classify_provider_error(stage, exc, attempts=attempts) from exc

    def plan(self, program_id: str, asset: str, context: dict[str, Any] | None = None) -> ProviderResult:
        schema = BenchmarkHypothesisBatch if asset == "lab://benchmark" else HypothesisBatch
        return self._call("planner", {"program_id": program_id, "asset": asset, **(context or {})}, schema)

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
        raw_timeout = os.getenv("ABB_LLM_TIMEOUT_SECONDS", "30")
        try:
            timeout_seconds = float(raw_timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError("ABB_LLM_TIMEOUT_SECONDS must be a finite positive number") from exc
        raw_retries = os.getenv("ABB_LLM_TRANSIENT_MAX_RETRIES", "2")
        try:
            transient_max_retries = int(raw_retries)
        except (TypeError, ValueError) as exc:
            raise ValueError("ABB_LLM_TRANSIENT_MAX_RETRIES must be a non-negative integer") from exc
        raw_backoff = os.getenv("ABB_LLM_TRANSIENT_BACKOFF_SECONDS", "2")
        try:
            transient_backoff_seconds = float(raw_backoff)
        except (TypeError, ValueError) as exc:
            raise ValueError("ABB_LLM_TRANSIENT_BACKOFF_SECONDS must be finite and non-negative") from exc
        return OpenAICompatibleProvider(
            base_url=base_url,
            model=model,
            api_key=api_key,
            network_enabled=network_enabled,
            input_price_per_million=_optional_float(os.getenv("ABB_LLM_INPUT_PRICE_PER_MILLION")),
            output_price_per_million=_optional_float(os.getenv("ABB_LLM_OUTPUT_PRICE_PER_MILLION")),
            timeout_seconds=timeout_seconds,
            transient_max_retries=transient_max_retries,
            transient_backoff_seconds=transient_backoff_seconds,
        )
    raise ValueError(f"Unknown provider: {name}")


def _optional_float(value: str | None) -> float | None:
    return float(value) if value not in {None, ""} else None


def _clean_json_content(content: str) -> str:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].strip().lower() in {"```", "```json"}:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def _merge_usage(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key in ("prompt_tokens", "completion_tokens"):
        left, right = first.get(key), second.get(key)
        merged[key] = left + right if isinstance(left, int) and isinstance(right, int) else None
    return merged


def _without_benchmark_oracle_fields(value: Any) -> Any:
    """Keep answer schemas useful without exposing expected status fields to a model."""
    if isinstance(value, dict):
        result = {key: _without_benchmark_oracle_fields(item) for key, item in value.items()}
        if isinstance(result.get("properties"), dict):
            result["properties"].pop("expected_status", None)
        if isinstance(result.get("required"), list):
            result["required"] = [item for item in result["required"] if item != "expected_status"]
        return result
    if isinstance(value, list):
        return [_without_benchmark_oracle_fields(item) for item in value]
    return value


def _benchmark_target_path(path: str) -> str:
    replacements = {
        "/api/documents/{id}": "/api/documents/doc-a",
        "/api/items/{id}": "/api/items/item-a",
        "/api/users/{id}": "/api/users/alice",
        "/api/records/{id}": "/api/records/record-a",
        "/api/metadata/{id}": "/api/metadata/item-1",
    }
    return replacements.get(path, path)


def _benchmark_kind(path: str) -> str:
    if path in {"/api/promotions/apply", "/api/promotions/submit"}:
        return "business"
    if path in {"/api/environment", "/api/environment/details", "/api/metadata/{id}"}:
        return "information"
    return "authorization"


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

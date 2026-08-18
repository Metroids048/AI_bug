import json

import httpx
import pytest

from ai_bug_bounty.benchmark_contracts import MODEL_INTERFACE_VERSION
from ai_bug_bounty.experiments import benchmark_version
from ai_bug_bounty.lab import benchmark_profile
from ai_bug_bounty.programs import authorize_program, create_benchmark_program
from ai_bug_bounty.providers import (
    BlindBenchmarkProvider,
    DeterministicProvider,
    OpenAICompatibleProvider,
    ProviderCallError,
)
from ai_bug_bounty.storage import Repository
from ai_bug_bounty.workflow import PlanContractViolation, Planner


@pytest.fixture
def repo(tmp_path):
    repository = Repository(tmp_path / "test.sqlite3")
    yield repository
    repository.close()


def _authorized_benchmark(repo):
    program = create_benchmark_program(repo)
    return authorize_program(repo, program.id, program.scope_hash())


class _CoverageProvider(BlindBenchmarkProvider):
    def __init__(self, mutation, repair_success=False):
        self.mutation = mutation
        self.repair_success = repair_success
        self.plan_calls = 0
        self.validation_calls = 0
        self.plan_contexts = []

    def plan(self, program_id, asset, context=None):
        self.plan_calls += 1
        self.plan_contexts.append(context or {})
        result = super().plan(program_id, asset, context)
        if self.plan_calls == 1 or not self.repair_success:
            result.data.hypotheses = self.mutation(result.data.hypotheses)
        return result

    def validation_plan(self, hypothesis, context):
        self.validation_calls += 1
        return super().validation_plan(hypothesis, context)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda hypotheses: hypotheses[:-1], id="missing"),
        pytest.param(lambda hypotheses: [*hypotheses, hypotheses[0]], id="duplicate"),
        pytest.param(
            lambda hypotheses: [
                *hypotheses[:-1],
                hypotheses[-1].model_copy(update={"operation_method": "DELETE"}),
            ],
            id="unknown-method",
        ),
        pytest.param(
            lambda hypotheses: [
                *hypotheses[:-1],
                hypotheses[-1].model_copy(update={"operation_path": "/api/unknown"}),
            ],
            id="unknown-path",
        ),
    ],
)
def test_invalid_benchmark_coverage_stops_before_validation(repo, mutation):
    program = _authorized_benchmark(repo)
    provider = _CoverageProvider(mutation)

    with pytest.raises(PlanContractViolation) as exc_info:
        Planner(repo, provider).plan(program, "lab://benchmark", benchmark_profile(program.id))

    assert exc_info.value.reason_code == "BENCHMARK_OPERATION_COVERAGE_INVALID"
    assert provider.plan_calls == 2
    assert provider.validation_calls == 0
    repair = provider.plan_contexts[1]["_benchmark_coverage_repair"]
    assert set(repair) == {"missing", "duplicate", "unknown"}
    assert "truth_vulnerable" not in json.dumps(repair).lower()
    assert "expected_status" not in json.dumps(repair).lower()


def test_benchmark_coverage_structural_repair_is_attempted_once_and_then_plans_all(repo):
    program = _authorized_benchmark(repo)
    provider = _CoverageProvider(lambda hypotheses: hypotheses[:-1], repair_success=True)

    hypotheses = Planner(repo, provider).plan(program, "lab://benchmark", benchmark_profile(program.id))

    assert len(hypotheses) == 9
    assert provider.plan_calls == 2
    assert provider.validation_calls == 9
    assert provider.plan_contexts[1]["_benchmark_coverage_repair"]["missing"]


def test_benchmark_planner_prompt_requires_exact_public_operation_coverage(monkeypatch):
    fixture = BlindBenchmarkProvider().plan("program", "lab://benchmark", {
        "operations": [{"method": "GET", "path": "/api/example", "description": "Example."}],
    })
    captured = {}

    def fake_post(*args, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, json={"choices": [{"message": {"content": fixture.data.model_dump_json()}}]})

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)
    provider.plan("program", "lab://benchmark", {
        "operations": [{"method": "GET", "path": "/api/example", "description": "Example."}],
        "_benchmark_coverage_repair": {
            "missing": [{"method": "GET", "path": "/api/example"}],
            "duplicate": [],
            "unknown": [],
        },
    })
    prompt = captured["json"]["messages"][0]["content"]
    assert "return exactly one hypothesis for every public operation in Context.operations" in prompt
    assert "Preserve each operation's method and path exactly." in prompt
    assert "Do not omit, duplicate, merge, invent, rank away, or replace operations." in prompt
    assert "This requirement describes experiment coverage only." in prompt
    assert '"method": "GET"' in prompt
    assert '"path": "/api/example"' in prompt
    for marker in (
        "truth_vulnerable",
        "scenario_truth",
        "expected_status",
        "expected_result",
        "should_pass",
        "should_fail",
        "semantic_assertion",
        "semantic_contract",
        "hidden_assertion",
    ):
        assert marker not in prompt.lower()


def test_model_interface_version_is_part_of_benchmark_hash(monkeypatch):
    import ai_bug_bounty.experiments as experiments

    baseline = benchmark_version()
    assert MODEL_INTERFACE_VERSION == "v1"
    monkeypatch.setattr(experiments, "MODEL_INTERFACE_VERSION", "v2")
    assert benchmark_version() != baseline


@pytest.mark.parametrize(
    ("status_code", "expected_reason"),
    [
        (401, "PROVIDER_AUTH"),
        (403, "PROVIDER_AUTH"),
        (429, "PROVIDER_RATE_LIMIT"),
        (400, "PROVIDER_REQUEST_REJECTED"),
    ],
)
def test_provider_http_failures_are_classified_without_retry(monkeypatch, status_code, expected_reason):
    calls = 0

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        response = httpx.Response(status_code, headers={"Retry-After": "7"})
        request = httpx.Request("POST", "http://model.local/v1/chat/completions")
        raise httpx.HTTPStatusError("request failed", request=request, response=response)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    with pytest.raises(ProviderCallError) as exc_info:
        provider.plan("program", "lab://idor")

    assert calls == 1
    assert exc_info.value.reason_code == expected_reason
    assert exc_info.value.stage == "planner"
    assert exc_info.value.http_status == status_code
    assert exc_info.value.retry_after == "7"
    assert exc_info.value.attempts == 1


def test_provider_timeout_is_classified_without_retry(monkeypatch):
    calls = 0

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    with pytest.raises(ProviderCallError) as exc_info:
        provider.plan("program", "lab://idor")

    assert calls == 1
    assert exc_info.value.reason_code == "PROVIDER_TIMEOUT"
    assert exc_info.value.stage == "planner"
    assert exc_info.value.http_status is None
    assert exc_info.value.retry_after is None
    assert exc_info.value.attempts == 1


def _queued_provider_response(status_code, payload=None):
    request = httpx.Request("POST", "http://model.local/v1/chat/completions")
    if payload is None:
        return httpx.Response(status_code, request=request)
    return httpx.Response(status_code, request=request, json=payload)


@pytest.mark.parametrize("transient_status", [502, 503, 504])
def test_provider_retries_transient_upstream_then_succeeds(monkeypatch, transient_status):
    fixture = DeterministicProvider().plan("program", "lab://idor")
    payload = {"choices": [{"message": {"content": fixture.data.model_dump_json()}}], "usage": {}}
    responses = [_queued_provider_response(transient_status), _queued_provider_response(200, payload)]
    calls = 0
    delays = []
    monkeypatch.setattr("time.sleep", lambda delay: delays.append(delay))

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    result = provider.plan("program", "lab://idor")

    assert result.data == fixture.data
    assert calls == 2
    assert delays == [2.0]


def test_provider_retries_503_twice_then_succeeds(monkeypatch):
    fixture = DeterministicProvider().plan("program", "lab://idor")
    payload = {"choices": [{"message": {"content": fixture.data.model_dump_json()}}], "usage": {}}
    responses = [_queued_provider_response(503), _queued_provider_response(503), _queued_provider_response(200, payload)]
    calls = 0
    delays = []
    monkeypatch.setattr("time.sleep", lambda delay: delays.append(delay))

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    result = provider.plan("program", "lab://idor")

    assert result.data == fixture.data
    assert calls == 3
    assert delays == [2.0, 4.0]


def test_provider_stops_after_two_transient_retries(monkeypatch):
    calls = 0
    delays = []
    monkeypatch.setattr("time.sleep", lambda delay: delays.append(delay))

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _queued_provider_response(503)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    with pytest.raises(ProviderCallError) as exc_info:
        provider.plan("program", "lab://idor")

    assert calls == 3
    assert delays == [2.0, 4.0]
    assert exc_info.value.reason_code == "PROVIDER_UPSTREAM"
    assert exc_info.value.attempts == 3


@pytest.mark.parametrize("status_code", [400, 401, 429])
def test_non_transient_provider_http_failures_are_not_retried(monkeypatch, status_code):
    calls = 0

    def fake_post(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _queued_provider_response(status_code)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)

    with pytest.raises(ProviderCallError):
        provider.plan("program", "lab://idor")

    assert calls == 1

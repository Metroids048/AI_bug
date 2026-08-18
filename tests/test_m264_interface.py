import json

import httpx
import pytest

from ai_bug_bounty.benchmark_contracts import MODEL_INTERFACE_VERSION
from ai_bug_bounty.experiments import benchmark_version
from ai_bug_bounty.lab import benchmark_profile
from ai_bug_bounty.programs import authorize_program, create_benchmark_program
from ai_bug_bounty.providers import BlindBenchmarkProvider, OpenAICompatibleProvider
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

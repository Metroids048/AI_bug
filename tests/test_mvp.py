from __future__ import annotations

import json
import socket

import httpx
import pytest

from ai_bug_bounty.cost import record_usage
from ai_bug_bounty.domain import (
    ActionProposal,
    Decision,
    Evidence,
    Finding,
    Hypothesis,
    Observation,
    PlatformResult,
    PlatformResultStatus,
    ProgramPolicySnapshot,
    ProgramState,
    ProviderUsage,
    ResearchState,
    Rules,
    ScopeRule,
    ValidationPlan,
    ValidationStep,
)
from ai_bug_bounty.evidence import EvidenceStore
from ai_bug_bounty.experiments import ExperimentRunner
from ai_bug_bounty.lab import LiveTargetBlocked, LocalLabExecutor, benchmark_profile
from ai_bug_bounty.policy import ScopeGuard, ScopeMatcher
from ai_bug_bounty.programs import authorize_program, create_benchmark_program, create_program
from ai_bug_bounty.providers import (
    BlindBenchmarkProvider,
    DeterministicProvider,
    OpenAICompatibleProvider,
    ProviderDisabled,
    provider_factory,
)
from ai_bug_bounty.reporting import ReportService
from ai_bug_bounty.state import InvalidTransition, transition_research
from ai_bug_bounty.storage import Repository
from ai_bug_bounty.workflow import Planner, ResearchOrchestrator, _provider_context


@pytest.fixture
def repo(tmp_path):
    repository = Repository(tmp_path / "test.sqlite3")
    yield repository
    repository.close()


@pytest.fixture
def authorized(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor", rules=explicit_rules(), allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"])
    return authorize_program(repo, program.id, program.scope_hash())


def explicit_rules() -> Rules:
    return Rules(
        rate_limit_per_minute=30,
        automation_allowed=True,
        cross_account_testing=True,
        test_account_rules="Use only researcher-owned test accounts.",
    )


def proposal(program_id: str, target: str = "lab://idor/api/documents/doc-a", action: str = "READ_OTHER_TEST_ACCOUNT_DATA"):
    return ActionProposal(
        program_id=program_id, hypothesis_id="h1", target=target, method="GET", action=action,
        risk="LOW", reason="test", account_role="account_b", expected_behavior="B must be denied",
    )


def test_unauthorized_and_out_of_scope_are_denied(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor", rules=explicit_rules(), allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"])
    guard = ScopeGuard(repo)
    assert guard.evaluate(proposal(program.id)).decision == Decision.DENY
    authorized_program = authorize_program(repo, program.id, program.scope_hash())
    assert guard.evaluate(proposal(authorized_program.id, "lab://other/api/documents/doc-a")).reason_code == "TARGET_OUT_OF_SCOPE"


def test_unknown_program_fails_closed_and_records_deny(repo):
    decision = ScopeGuard(repo).evaluate(proposal("missing-program"))
    assert decision.decision == Decision.DENY
    assert decision.reason_code == "POLICY_ERROR"
    assert repo.replay()[-1].event_type == "POLICY_DENY"


def test_forbidden_action_and_method_are_denied(authorized, repo):
    guard = ScopeGuard(repo)
    assert guard.evaluate(proposal(authorized.id, action="DOS")).reason_code == "ACTION_FORBIDDEN"
    post = proposal(authorized.id)
    post.method = "POST"
    assert guard.evaluate(post).reason_code == "METHOD_NOT_ALLOWED"


def test_scope_change_revokes_authorization(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor", rules=explicit_rules(), allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"])
    authorize_program(repo, program.id, program.scope_hash())
    program.scopes.append(ScopeRule(asset="lab://other"))
    repo.save("program", program, program.id, "PROGRAM_SCOPE_CHANGED")
    reloaded = repo.get_program(program.id)
    assert reloaded.state == ProgramState.REVIEW_REQUIRED
    assert reloaded.authorization_hash is None


def test_policy_snapshot_content_tampering_is_denied(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor", rules=explicit_rules(), allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"])
    authorized_program = authorize_program(repo, program.id, program.scope_hash())
    snapshot = repo.get("policy_snapshot", authorized_program.policy_snapshot_id or "", ProgramPolicySnapshot)
    assert snapshot is not None
    snapshot.raw_policy += "\nTAMPERED"
    repo.save("policy_snapshot", snapshot, authorized_program.id, "POLICY_SNAPSHOT_TAMPERED")
    reloaded = repo.get_program(authorized_program.id)
    assert reloaded.state == ProgramState.REVIEW_REQUIRED
    assert reloaded.authorization_hash is None
    decision = ScopeGuard(repo).evaluate(proposal(authorized_program.id))
    assert decision.decision == Decision.DENY
    assert decision.reason_code == "PROGRAM_NOT_AUTHORIZED"


def test_evidence_is_redacted_and_reloadable(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor", rules=explicit_rules(), allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"])
    program = authorize_program(repo, program.id, program.scope_hash())
    decision = ScopeGuard(repo).evaluate(proposal(program.id))
    observation = Observation(
        hypothesis_id="h1", reproduction_number=1, expected_behavior="deny", actual_behavior="private data",
        response_status=200,
        response_body={"email": "alice@example.test", "session_token": "secret-token", "private_note": "hello"},
        request_metadata={"Authorization": "Bearer top-secret", "target": "lab://idor"},
        account_role="account_b", success=True,
    )
    evidence = EvidenceStore(repo).persist(observation, decision, "Unauthorized private data observed")
    stored = repo.get("evidence", evidence.id, type(evidence))
    serialized = json.dumps(stored.model_dump(mode="json"))
    assert stored.redacted and stored.complete
    assert "top-secret" not in serialized
    assert "alice@example.test" not in serialized
    assert "secret-token" not in serialized


def test_offline_golden_path_true_and_false(repo, authorized, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("offline workflow attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    hypotheses = Planner(repo, DeterministicProvider()).plan(authorized, "lab://idor")
    results = [ResearchOrchestrator(repo, DeterministicProvider(), LocalLabExecutor()).run(authorized, item) for item in hypotheses[:2]]
    assert results[0].state == ResearchState.SUBMISSION_READY
    assert results[1].state == ResearchState.INVALID
    draft = ReportService(repo).generate(results[0])
    assert "Observed Impact" in draft.markdown
    assert "alice@example.test" not in draft.markdown


def test_non_lab_executor_is_hard_blocked(authorized):
    blocked = proposal(authorized.id, "https://example.com/api")
    with pytest.raises(LiveTargetBlocked):
        LocalLabExecutor().execute(blocked)


def test_cost_unknown_is_not_zero(repo):
    record_usage(repo, "test", "model", "task", ProviderUsage(input_tokens=None, output_tokens=None), None, None)
    summary = repo.cost_summary()
    assert summary["known_total"] == 0.0
    assert summary["unknown_entries"] == 1


def test_cost_price_propagation_calculates_known_cost(repo):
    record_usage(repo, "model", "v1", "planner", ProviderUsage(input_tokens=100, output_tokens=200), 1.0, 2.0)
    summary = repo.cost_summary()
    assert summary["known_total"] == pytest.approx(0.0005)
    assert summary["unknown_entries"] == 0


def test_disabled_compatible_provider_does_not_call_network():
    provider = OpenAICompatibleProvider("http://127.0.0.1:9/v1", "model", "secret", network_enabled=False)
    with pytest.raises(ProviderDisabled):
        provider.plan("program", "lab://idor")


def test_compatible_provider_contract_returns_usage_and_prices(monkeypatch):
    fixture = DeterministicProvider().plan("program", "lab://idor")
    response_payload = {
        "choices": [{"message": {"content": fixture.data.model_dump_json()}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }

    def fake_post(*args, **kwargs):
        return httpx.Response(200, json=response_payload)

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider(
        "http://model.local/v1", "deepseek-chat", "test-key", network_enabled=True,
        input_price_per_million=0.5, output_price_per_million=1.0,
    )
    result = provider.plan("program", "lab://idor")
    assert result.usage.input_tokens == 11
    assert result.usage.output_tokens == 7
    assert result.input_price_per_million == 0.5
    assert result.output_price_per_million == 1.0


def test_real_provider_context_contains_no_benchmark_oracle(monkeypatch):
    fixture = DeterministicProvider().plan("program", "lab://benchmark")
    captured: dict[str, object] = {}

    def fake_post(*args, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, json={"choices": [{"message": {"content": fixture.data.model_dump_json()}}]})

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)
    provider.plan("program", "lab://benchmark", _provider_context(benchmark_profile("program")))
    prompt = captured["json"]["messages"][0]["content"]
    assert "control_target" not in prompt
    assert "test_target" not in prompt
    assert "truth_vulnerable" not in prompt
    assert '"test_resources"' in prompt
    assert '"doc-a"' in prompt
    assert '"promotion_code": "WELCOME"' in prompt
    assert "shared-doc" not in prompt


def test_research_fixture_metadata_is_neutral_and_structured():
    profile = benchmark_profile("program")
    context = _provider_context(profile)
    assert context["test_accounts"] == ["account_a", "account_b"]
    assert context["test_resources"] == {
        "document_a": {"id": "doc-a", "created_by": "account_a"},
        "item_a": {"id": "item-a", "created_by": "account_a"},
        "record_a": {"id": "record-a", "created_by": None},
        "metadata_a": {"id": "item-1", "created_by": None},
    }
    assert context["test_inputs"] == {"promotion_code": "WELCOME"}
    serialized = json.dumps(context, sort_keys=True).lower()
    for marker in ("truth_vulnerable", "expected_status", "should_deny", "vulnerable", "safe", "shared-doc"):
        assert marker not in serialized


def test_compatible_provider_includes_schema_and_repairs_once(monkeypatch):
    fixture = DeterministicProvider().plan("program", "lab://idor")
    responses = [
        {"choices": [{"message": {"content": "{\"invalid\": true}"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}},
        {"choices": [{"message": {"content": fixture.data.model_dump_json()}}], "usage": {"prompt_tokens": 5, "completion_tokens": 7}},
    ]
    prompts: list[str] = []

    def fake_post(*args, **kwargs):
        prompts.append(kwargs["json"]["messages"][0]["content"])
        return httpx.Response(200, json=responses[len(prompts) - 1])

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True)
    result = provider.plan("program", "lab://idor")
    assert len(prompts) == 2
    assert "JSON Schema" in prompts[0]
    assert "hypotheses" in prompts[0]
    assert "schema validation" in prompts[1]
    assert result.usage.input_tokens == 8
    assert result.usage.output_tokens == 9


def test_provider_factory_reads_llm_timeout_seconds(monkeypatch):
    monkeypatch.setenv("ABB_LLM_TIMEOUT_SECONDS", "180")
    provider = provider_factory("openai-compatible")
    assert provider.timeout_seconds == 180.0


def test_compatible_provider_uses_configured_timeout(monkeypatch):
    fixture = DeterministicProvider().plan("program", "lab://idor")
    captured: dict[str, object] = {}

    def fake_post(*args, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, json={"choices": [{"message": {"content": fixture.data.model_dump_json()}}], "usage": {}})

    monkeypatch.setattr(httpx, "post", fake_post)
    provider = OpenAICompatibleProvider("http://model.local/v1", "model", "key", network_enabled=True, timeout_seconds=180.0)
    provider.plan("program", "lab://idor")
    assert captured["timeout"] == 180.0


@pytest.mark.parametrize("value", ["abc", "0", "-1"])
def test_invalid_llm_timeout_is_rejected(monkeypatch, value):
    monkeypatch.setenv("ABB_LLM_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError):
        provider_factory("openai-compatible")


def test_invalid_state_transition_is_rejected():
    with pytest.raises(InvalidTransition):
        transition_research(ResearchState.HYPOTHESIS, ResearchState.SUBMISSION_READY)


def test_scope_matcher_supports_path_port_wildcard_and_deny_precedence():
    matcher = ScopeMatcher()
    assert matcher.matches("https://example.com/test-api/*", "https://example.com/test-api/users")
    assert not matcher.matches("https://example.com/test-api/*", "https://example.com/admin/delete")
    assert matcher.matches("https://*.example.com:8443/api/*", "https://api.example.com:8443/api/v1")
    assert not matcher.matches("https://*.example.com:8443/api/*", "https://example.com:8443/api/v1")
    assert not matcher.matches("https://example.com:8443/api/*", "https://example.com/api/v1")


def test_out_of_scope_precedence_and_unknown_policy_rejection(repo):
    rules = Rules(
        rate_limit_per_minute=30,
        automation_allowed=True,
        cross_account_testing=True,
        test_account_rules="Researcher-owned accounts only.",
        out_of_scope=["https://example.com/test-api/admin/*"],
    )
    program = create_program(
        repo, "Scoped", "local", None, "https://example.com/test-api/*",
        rules=rules, allowed_actions=["READ"],
    )
    authorized_program = authorize_program(repo, program.id, program.scope_hash())
    guard = ScopeGuard(repo)
    allowed = proposal(authorized_program.id, "https://example.com/test-api/users", action="READ")
    denied = proposal(authorized_program.id, "https://example.com/test-api/admin/delete", action="READ")
    assert guard.evaluate(allowed).decision == Decision.ALLOW
    assert guard.evaluate(denied).reason_code == "TARGET_OUT_OF_SCOPE"
    unknown = create_program(repo, "Unknown", "local", None, "lab://idor")
    with pytest.raises(ValueError, match="UNKNOWN"):
        authorize_program(repo, unknown.id, unknown.scope_hash())


def test_blind_benchmark_finds_vulnerable_cases_and_rejects_controls(repo, monkeypatch):
    program = create_benchmark_program(repo)
    authorized_program = authorize_program(repo, program.id, program.scope_hash())
    profile = benchmark_profile(program.id)

    def no_network(*args, **kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    hypotheses = Planner(repo, BlindBenchmarkProvider()).plan(authorized_program, "lab://benchmark", profile)
    assert len(hypotheses) == 9
    orchestrator = ResearchOrchestrator(repo, BlindBenchmarkProvider(), LocalLabExecutor(lab_name="benchmark"))
    findings = [orchestrator.run(authorized_program, hypothesis, profile) for hypothesis in hypotheses]
    by_feature = {finding.title: finding.state for finding in findings}
    assert any("/api/documents/{id}" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/environment" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/promotions/apply" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/items/{id}" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/environment/details" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/promotions/submit" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/users/{id}" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/records/{id}" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/metadata/{id}" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    evidence = repo.get("evidence", findings[0].evidence_ids[0], Evidence)
    serialized = json.dumps(evidence.model_dump(mode="json"))
    assert "alice@example.test" not in serialized
    assert "ACCOUNT_A_EMAIL" in serialized or "ACCOUNT_B_EMAIL" in serialized


def test_bounty_ledger_produces_real_roi_metrics(repo, authorized):
    finding = Finding(
        program_id=authorized.id, hypothesis_id="h", asset="lab://idor", category="authorization",
        title="Test", security_boundary="A/B", expected_behavior="deny", actual_behavior="observed",
        observed_impact="impact", potential_impact="potential", state=ResearchState.SUBMISSION_READY,
    )
    repo.save("finding", finding, authorized.id)
    result = PlatformResult(
        finding_id=finding.id, program_id=authorized.id, submission_id="SUB-1",
        status=PlatformResultStatus.PAID, reward=125.0, currency="USD",
    )
    repo.save("platform_result", result, authorized.id)
    summary = repo.roi_summary(authorized.id)
    assert summary["paid_revenue"] == 125.0
    assert summary["net_profit"] == 125.0


def test_m26_three_round_nine_case_metrics_and_no_oracle_context(repo, monkeypatch):
    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    serialized = json.dumps(_provider_context(profile), sort_keys=True)
    assert "control_target" not in serialized
    assert "test_target" not in serialized
    assert "truth_vulnerable" not in serialized
    semantic_context = json.dumps({key: value for key, value in _provider_context(profile).items() if key != "public_brief"}, sort_keys=True).lower()
    for marker in ("secure", "ownership control", "public", "shared", "non-sensitive", "state handling", '"kind"'):
        assert marker not in semantic_context
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    runs = ExperimentRunner(repo, BlindBenchmarkProvider()).run(program, profile, rounds=3)
    assert len(runs) == 3
    summary = repo.experiment_summary(program.id)
    assert summary["case_runs"] == 27
    assert summary["true_positive"] == 9
    assert summary["false_positive"] == 0
    assert summary["false_negative"] == 0
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["scope_violations"] == 0
    assert summary["reproduction_failures"] == 0
    assert summary["evidence_failures"] == 0
    assert summary["gate_passed"] is True
    assert summary["gate_failures"] == []


def test_three_round_blind_and_one_round_weak_batch_are_isolated(repo, monkeypatch):
    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    blind_runs = ExperimentRunner(repo, BlindBenchmarkProvider()).run(program, profile, rounds=3)
    weak_runs = ExperimentRunner(repo, DeterministicProvider()).run(program, profile, rounds=1)
    blind_batch = repo.get("experiment_batch", blind_runs[0].experiment_batch_id, __import__("ai_bug_bounty.domain", fromlist=["ExperimentBatch"]).ExperimentBatch)
    weak_batch = repo.get("experiment_batch", weak_runs[0].experiment_batch_id, __import__("ai_bug_bounty.domain", fromlist=["ExperimentBatch"]).ExperimentBatch)
    assert blind_batch and weak_batch and blind_batch.id != weak_batch.id
    assert repo.experiment_summary(batch_id=blind_batch.id)["gate_passed"] is True
    weak_summary = repo.experiment_summary(batch_id=weak_batch.id)
    assert weak_summary["runs"] == 1
    assert weak_summary["gate_passed"] is False
    assert "insufficient_rounds" in weak_summary["gate_failures"]


def test_weak_three_round_batch_cannot_be_saved_by_blind_history(repo, monkeypatch):
    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    ExperimentRunner(repo, BlindBenchmarkProvider()).run(program, profile, rounds=3)
    weak_runs = ExperimentRunner(repo, DeterministicProvider()).run(program, profile, rounds=3)
    summary = repo.experiment_summary(batch_id=weak_runs[0].experiment_batch_id)
    assert summary["case_runs"] == 27
    assert summary["gate_passed"] is False


def test_program_summary_requires_explicit_batch_when_multiple_exist(repo):
    from ai_bug_bounty.domain import ExperimentBatch, ExperimentBatchStatus
    for provider in ("blind-benchmark", "other"):
        repo.save("experiment_batch", ExperimentBatch(program_id="p", provider=provider, model="m", benchmark_version="v", requested_rounds=3, run_ids=[], status=ExperimentBatchStatus.COMPLETED), "p")
    with pytest.raises(ValueError, match="batch_id"):
        repo.experiment_summary(program_id="p")


def test_legacy_unbatched_runs_are_readable_but_not_gate_eligible(repo):
    from ai_bug_bounty.domain import ExperimentRun
    run = ExperimentRun(program_id="p", provider="legacy", model="m", round_number=1, context_hash="h", total_cases=0)
    repo.save("experiment_run", run, "p")
    summary = repo.experiment_summary(program_id="p")
    assert summary["runs"] == 1
    assert summary["gate_passed"] is False
    assert "legacy_unbatched" in summary["gate_failures"]


def test_experiment_list_reports_independent_batches(repo):
    from ai_bug_bounty.domain import ExperimentBatch
    first = ExperimentBatch(program_id="p", provider="blind", model="m1", benchmark_version="v1", requested_rounds=3, run_ids=[])
    second = ExperimentBatch(program_id="p", provider="weak", model="m2", benchmark_version="v1", requested_rounds=1, run_ids=[])
    repo.save("experiment_batch", first, "p")
    repo.save("experiment_batch", second, "p")
    batches = repo.experiment_list("p")
    assert [item.id for item in batches] == [first.id, second.id]


def test_benchmark_version_is_stable_for_same_contract():
    from ai_bug_bounty.experiments import benchmark_version
    assert benchmark_version() == benchmark_version()


def _benchmark_hypothesis(program_id: str, method: str = "GET", path: str = "/api/documents/{id}"):
    return Hypothesis(
        program_id=program_id, asset="lab://benchmark", category="authorization", feature="human text that is not an identity",
        operation_method=method, operation_path=path,
        expected_security_boundary="Account B must not read Account A private document.",
        hypothesis="The operation may cross a boundary.", reason="test", validation_plan="control and test",
        required_accounts=["account_a", "account_b"], confidence=0.8,
    )


def _benchmark_plan(hypothesis_id: str, target: str = "lab://benchmark/api/documents/doc-a", phases=("CONTROL", "TEST")):
    return ValidationPlan(
        hypothesis_id=hypothesis_id, objective="test", steps=[
            ValidationStep(phase=phases[0], target=target, method="GET", action="READ", account_role="account_a", resource_key="document_a", expected_behavior="control"),
            ValidationStep(phase=phases[1], target=target, method="GET", action="READ_OTHER_TEST_ACCOUNT_DATA", account_role="account_b", resource_key="document_a", expected_behavior="test"),
        ],
    )


def test_feature_text_is_not_used_as_machine_operation_identity():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    hypothesis.feature = "GET lab://benchmark/api/environment"
    assert validate_benchmark_plan(hypothesis, _benchmark_plan(hypothesis.id), benchmark_profile("p")) is None


def test_documents_hypothesis_cannot_score_environment_execution():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    plan = _benchmark_plan(hypothesis.id, "lab://benchmark/api/environment")
    assert validate_benchmark_plan(hypothesis, plan, benchmark_profile("p")) == "SCENARIO_MISMATCH"


def test_missing_control_is_contract_failure_before_execution():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    plan = _benchmark_plan(hypothesis.id, phases=("TEST", "TEST"))
    assert validate_benchmark_plan(hypothesis, plan, benchmark_profile("p")) == "MISSING_CONTROL"


def test_missing_test_is_contract_failure_before_execution():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    plan = _benchmark_plan(hypothesis.id, phases=("CONTROL", "CONTROL"))
    assert validate_benchmark_plan(hypothesis, plan, benchmark_profile("p")) == "MISSING_TEST"


def test_multi_operation_plan_is_contract_failure():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    plan = ValidationPlan(hypothesis_id=hypothesis.id, objective="test", steps=[
        _benchmark_plan(hypothesis.id).steps[0],
        ValidationStep(phase="TEST", target="lab://benchmark/api/environment", method="GET", action="READ", account_role="account_b", resource_key="environment", expected_behavior="test"),
    ])
    assert validate_benchmark_plan(hypothesis, plan, benchmark_profile("p")) == "MULTI_OPERATION_PLAN"


def test_validation_plan_hypothesis_id_mismatch_is_rejected():
    from ai_bug_bounty.workflow import validate_benchmark_plan
    hypothesis = _benchmark_hypothesis("p")
    assert validate_benchmark_plan(hypothesis, _benchmark_plan("other"), benchmark_profile("p")) == "VALIDATION_PLAN_HYPOTHESIS_MISMATCH"


def test_openai_benchmark_schema_requires_operation_method_and_path():
    from ai_bug_bounty.providers import BenchmarkHypothesisBatch
    schema = BenchmarkHypothesisBatch.model_json_schema()
    item = schema["$defs"]["BenchmarkHypothesis"]
    assert "operation_method" in item["required"]
    assert "operation_path" in item["required"]


def test_executed_targets_match_declared_operation_for_valid_case(repo, monkeypatch):
    from ai_bug_bounty.workflow import resolve_benchmark_operation
    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    ExperimentRunner(repo, BlindBenchmarkProvider()).run(program, profile, rounds=1)
    cases = repo.list("experiment_case_result", __import__("ai_bug_bounty.domain", fromlist=["ExperimentCaseResult"]).ExperimentCaseResult, program.id)
    valid = [item for item in cases if item.contract_valid]
    assert valid
    assert all(
        item.executed_targets
        and item.executed_methods
        and resolve_benchmark_operation(item.executed_methods[0], item.executed_targets[0], profile.api_spec["operations"])["path"] == item.declared_operation_path
        for item in valid
    )


def test_scenario_mismatch_active_chain_documents_hypothesis_cannot_score_environment(repo, monkeypatch):
    class ScenarioMismatchProvider(BlindBenchmarkProvider):
        def validation_plan(self, hypothesis, context):
            result = super().validation_plan(hypothesis, context)
            if hypothesis.operation_path == "/api/documents/{id}":
                result.data.steps[0].target = "lab://benchmark/api/environment"
                result.data.steps[1].target = "lab://benchmark/api/environment"
            return result

    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    runs = ExperimentRunner(repo, ScenarioMismatchProvider()).run(program, profile, rounds=1)
    cases = repo.list("experiment_case_result", __import__("ai_bug_bounty.domain", fromlist=["ExperimentCaseResult"]).ExperimentCaseResult, program.id)
    documents = next(item for item in cases if item.scenario_key == "/api/documents/{id}")
    summary = repo.experiment_summary(batch_id=runs[0].experiment_batch_id)
    assert documents.true_positive is False
    assert documents.contract_valid is False
    assert documents.contract_reason_code == "SCENARIO_MISMATCH"
    assert documents.executed_targets == []
    assert summary["gate_passed"] is False


def _fresh_benchmark_finding(repo, monkeypatch, scenario_path: str):
    program = authorize_program(repo, (created := create_benchmark_program(repo)).id, created.scope_hash())
    profile = benchmark_profile(program.id)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    ExperimentRunner(repo, BlindBenchmarkProvider()).run(program, profile, rounds=1)
    cases = repo.list("experiment_case_result", __import__("ai_bug_bounty.domain", fromlist=["ExperimentCaseResult"]).ExperimentCaseResult, program.id)
    case = next(item for item in cases if item.scenario_key == scenario_path)
    return repo.get("finding", case.finding_id, Finding)


def test_authorization_report_steps_come_from_validation_plan(repo, monkeypatch):
    finding = _fresh_benchmark_finding(repo, monkeypatch, "/api/documents/{id}")
    draft = ReportService(repo).generate(finding)
    assert "CONTROL" in draft.markdown and "TEST" in draft.markdown
    assert "lab://benchmark/api/documents/doc-a" in draft.markdown
    assert "two researcher-owned test accounts" not in draft.markdown


def test_information_report_does_not_use_idor_template(repo, monkeypatch):
    finding = _fresh_benchmark_finding(repo, monkeypatch, "/api/environment")
    draft = ReportService(repo).generate(finding)
    assert "lab://benchmark/api/environment" in draft.markdown
    assert "Account A document identifier" not in draft.markdown


def test_business_report_does_not_use_document_template(repo, monkeypatch):
    finding = _fresh_benchmark_finding(repo, monkeypatch, "/api/promotions/apply")
    draft = ReportService(repo).generate(finding)
    assert "lab://benchmark/api/promotions/apply" in draft.markdown
    assert "Account A document identifier" not in draft.markdown


def test_report_evidence_remains_redacted(repo, monkeypatch):
    finding = _fresh_benchmark_finding(repo, monkeypatch, "/api/documents/{id}")
    draft = ReportService(repo).generate(finding)
    assert "alice@example.test" not in draft.markdown
    assert "secret-token" not in draft.markdown


def test_neutral_benchmark_routes_return_expected_safe_controls():
    executor = LocalLabExecutor(lab_name="benchmark")
    for target, expected in [
        ("lab://benchmark/api/items/item-a", 403),
        ("lab://benchmark/api/environment/details", 200),
        ("lab://benchmark/api/promotions/submit", 200),
        ("lab://benchmark/api/users/alice", 200),
        ("lab://benchmark/api/records/record-a", 200),
        ("lab://benchmark/api/metadata/item-1", 200),
    ]:
        observation = executor.execute(ActionProposal(
            program_id="p", hypothesis_id="h", target=target, method="POST" if "promotions" in target else "GET",
            action="WRITE_TEST_DATA" if "promotions" in target else "READ", risk="LOW", reason="test",
            account_role="account_b", expected_behavior="response",
            request_payload={"code": "WELCOME"} if "promotions" in target else None,
        ))
        assert observation.response_status == expected
        if target.endswith("environment/details"):
            assert "internal_email" not in observation.response_body

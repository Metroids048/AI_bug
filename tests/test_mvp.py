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
    Observation,
    PlatformResult,
    PlatformResultStatus,
    ProgramPolicySnapshot,
    ProgramState,
    ProviderUsage,
    ResearchState,
    Rules,
    ScopeRule,
)
from ai_bug_bounty.evidence import EvidenceStore
from ai_bug_bounty.lab import LiveTargetBlocked, LocalLabExecutor, benchmark_profile
from ai_bug_bounty.policy import ScopeGuard, ScopeMatcher
from ai_bug_bounty.programs import authorize_program, create_benchmark_program, create_program
from ai_bug_bounty.providers import (
    BlindBenchmarkProvider,
    DeterministicProvider,
    OpenAICompatibleProvider,
    ProviderDisabled,
)
from ai_bug_bounty.reporting import ReportService
from ai_bug_bounty.state import InvalidTransition, transition_research
from ai_bug_bounty.storage import Repository
from ai_bug_bounty.workflow import Planner, ResearchOrchestrator


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
    assert len(hypotheses) == 6
    orchestrator = ResearchOrchestrator(repo, BlindBenchmarkProvider(), LocalLabExecutor(lab_name="benchmark"))
    findings = [orchestrator.run(authorized_program, hypothesis, profile) for hypothesis in hypotheses]
    by_feature = {finding.title: finding.state for finding in findings}
    assert any("/api/documents/{id}" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/config" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/rewards/redeem" in title and state == ResearchState.SUBMISSION_READY for title, state in by_feature.items())
    assert any("/api/secure-documents/{id}" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/secure-config" in title and state == ResearchState.INVALID for title, state in by_feature.items())
    assert any("/api/secure-rewards/redeem" in title and state == ResearchState.INVALID for title, state in by_feature.items())
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

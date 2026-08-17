from __future__ import annotations

import json
import socket

import pytest

from ai_bug_bounty.cost import record_usage
from ai_bug_bounty.domain import (
    ActionProposal,
    Decision,
    Observation,
    ProgramState,
    ProviderUsage,
    ResearchState,
    ScopeRule,
)
from ai_bug_bounty.evidence import EvidenceStore
from ai_bug_bounty.lab import LiveTargetBlocked, LocalLabExecutor
from ai_bug_bounty.policy import ScopeGuard
from ai_bug_bounty.programs import authorize_program, create_program
from ai_bug_bounty.providers import DeterministicProvider, OpenAICompatibleProvider, ProviderDisabled
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
    program = create_program(repo, "Offline", "local", None, "lab://idor")
    return authorize_program(repo, program.id, program.scope_hash())


def proposal(program_id: str, target: str = "lab://idor/api/documents/doc-a", action: str = "READ_OTHER_TEST_ACCOUNT_DATA"):
    return ActionProposal(
        program_id=program_id, hypothesis_id="h1", target=target, method="GET", action=action,
        risk="LOW", reason="test", account_role="account_b", expected_behavior="B must be denied",
    )


def test_unauthorized_and_out_of_scope_are_denied(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor")
    guard = ScopeGuard(repo)
    assert guard.evaluate(proposal(program.id)).decision == Decision.DENY
    authorized_program = authorize_program(repo, program.id, program.scope_hash())
    assert guard.evaluate(proposal(authorized_program.id, "lab://other/api/documents/doc-a")).reason_code == "TARGET_OUT_OF_SCOPE"


def test_forbidden_action_and_method_are_denied(authorized, repo):
    guard = ScopeGuard(repo)
    assert guard.evaluate(proposal(authorized.id, action="DOS")).reason_code == "ACTION_FORBIDDEN"
    post = proposal(authorized.id)
    post.method = "POST"
    assert guard.evaluate(post).reason_code == "METHOD_NOT_ALLOWED"


def test_scope_change_revokes_authorization(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor")
    authorize_program(repo, program.id, program.scope_hash())
    program.scopes.append(ScopeRule(asset="lab://other"))
    repo.save("program", program, program.id, "PROGRAM_SCOPE_CHANGED")
    reloaded = repo.get_program(program.id)
    assert reloaded.state == ProgramState.REVIEW_REQUIRED
    assert reloaded.authorization_hash is None


def test_evidence_is_redacted_and_reloadable(repo):
    program = create_program(repo, "Offline", "local", None, "lab://idor")
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


def test_disabled_compatible_provider_does_not_call_network():
    provider = OpenAICompatibleProvider("http://127.0.0.1:9/v1", "model", "secret", network_enabled=False)
    with pytest.raises(ProviderDisabled):
        provider.plan("program", "lab://idor")


def test_invalid_state_transition_is_rejected():
    with pytest.raises(InvalidTransition):
        transition_research(ResearchState.HYPOTHESIS, ResearchState.SUBMISSION_READY)

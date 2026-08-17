from __future__ import annotations

from .domain import Program, ProgramPolicySnapshot, ProgramState, Rules, ScopeRule, now_utc
from .state import transition_program
from .storage import Repository


def create_program(
    repository: Repository,
    name: str,
    platform: str,
    program_url: str | None,
    asset: str,
    allowed_methods: list[str] | None = None,
    rules: Rules | None = None,
    allowed_actions: list[str] | None = None,
    raw_policy: str | None = None,
    out_of_scope: list[str] | None = None,
) -> Program:
    resolved_rules = rules or Rules(out_of_scope=out_of_scope or [])
    program = Program(
        name=name,
        platform=platform,
        program_url=program_url,
        scopes=[ScopeRule(asset=asset, allowed_methods=allowed_methods or ["GET"], allowed_actions=allowed_actions or ["READ"])],
        rules=resolved_rules,
    )
    raw = raw_policy or f"IN_SCOPE: {asset}\nOUT_OF_SCOPE: {', '.join(resolved_rules.out_of_scope)}"
    snapshot = ProgramPolicySnapshot.create(
        program_id=program.id,
        raw_policy=raw,
        source_url=program_url,
        parsed_scope=[asset],
        parsed_out_of_scope=resolved_rules.out_of_scope,
        parsed_rules=resolved_rules.model_dump(mode="json"),
    )
    program.policy_snapshot_id = snapshot.id
    program.policy_snapshot_hash = snapshot.policy_hash
    repository.save("policy_snapshot", snapshot, program.id, "POLICY_SNAPSHOT_CREATED")
    repository.save("program", program, program.id, "PROGRAM_CREATED")
    return program


def authorize_program(repository: Repository, program_id: str, scope_hash: str) -> Program:
    program = repository.get_program(program_id)
    if scope_hash != program.scope_hash():
        raise ValueError("Scope hash does not match the current Scope/Rules snapshot.")
    if program.rules.automation_allowed is None:
        raise ValueError("Automation policy is UNKNOWN; explicit rules are required before authorization.")
    if program.rules.cross_account_testing is None:
        raise ValueError("Cross-account testing policy is UNKNOWN; explicit rules are required before authorization.")
    if program.rules.rate_limit_per_minute is None or not program.rules.test_account_rules:
        raise ValueError("Rate limit and test-account rules must be explicitly captured before authorization.")
    snapshot = repository.get("policy_snapshot", program.policy_snapshot_id or "", ProgramPolicySnapshot)
    if (
        snapshot is None
        or snapshot.policy_hash != program.policy_snapshot_hash
        or snapshot.policy_hash != snapshot.content_hash()
        or snapshot.parsed_scope != [rule.asset for rule in program.scopes]
        or snapshot.parsed_out_of_scope != program.rules.out_of_scope
        or snapshot.parsed_rules != program.rules.model_dump(mode="json")
    ):
        raise ValueError("Program Policy Snapshot is missing or does not match the Program.")
    snapshot.human_confirmed = True
    repository.save("policy_snapshot", snapshot, program.id, "POLICY_SNAPSHOT_CONFIRMED")
    program.state = transition_program(program.state, ProgramState.AUTHORIZED)
    program.authorization_hash = scope_hash
    program.authorized_at = now_utc()
    program.updated_at = now_utc()
    repository.save("program", program, program.id, "PROGRAM_AUTHORIZED")
    return program


def create_benchmark_program(repository: Repository) -> Program:
    return create_program(
        repository,
        name="Blind Offline Security Benchmark",
        platform="local",
        program_url="lab://benchmark",
        asset="lab://benchmark",
        allowed_methods=["GET", "POST"],
        allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA", "WRITE_TEST_DATA"],
        rules=Rules(
            rate_limit_per_minute=30,
            automation_allowed=True,
            cross_account_testing=True,
            test_account_rules="Use only account_a and account_b, both researcher-owned.",
        ),
        raw_policy=(
            "IN_SCOPE: lab://benchmark\n"
            "OUT_OF_SCOPE: all network targets\n"
            "AUTOMATION: explicitly allowed for the local fixture\n"
            "ACCOUNTS: account_a, account_b"
        ),
    )

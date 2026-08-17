from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .domain import (
    ActionProposal,
    Decision,
    PolicyDecision,
    Program,
    ProgramPolicySnapshot,
    ProgramState,
)
from .storage import Repository

READ_ACTIONS = {"READ", "READ_OWN_DATA", "READ_OTHER_TEST_ACCOUNT_DATA"}
SAFE_LOCAL_WRITE_ACTIONS = {"WRITE_TEST_DATA"}
BLOCKED_ACTIONS = {
    "DOS", "STRESS_TEST", "CREDENTIAL_STUFFING", "DELETE_REAL_DATA", "MODIFY_OTHER_USER_DATA",
    "REAL_PAYMENT", "FUNDS_TRANSFER", "LATERAL_MOVEMENT", "PERSISTENCE", "MALWARE", "MASS_DATA_ACCESS",
}


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


@dataclass(frozen=True)
class ParsedAsset:
    scheme: str
    host: str
    port: int | None
    path: str
    host_wildcard: bool
    path_wildcard: bool


class InvalidAssetPattern(ValueError):
    pass


def parse_asset_pattern(value: str) -> ParsedAsset:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https", "lab"} or not parsed.netloc:
        raise InvalidAssetPattern(f"Unsupported asset pattern: {value}")
    if parsed.query or parsed.fragment:
        raise InvalidAssetPattern("Scope patterns cannot contain query strings or fragments.")
    try:
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise InvalidAssetPattern(f"Invalid port in asset pattern: {value}") from exc
    if not hostname:
        raise InvalidAssetPattern(f"Asset pattern has no host: {value}")
    host_wildcard = hostname.startswith("*.")
    if host_wildcard:
        hostname = hostname[2:]
        if not hostname:
            raise InvalidAssetPattern("Wildcard host must have a suffix.")
    path = parsed.path or "/"
    path_wildcard = path.endswith("/*") or (parsed.scheme == "lab" and parsed.path == "")
    if path.endswith("/*"):
        path = path[:-2] or "/"
    return ParsedAsset(
        scheme=parsed.scheme.lower(),
        host=hostname,
        port=port if port is not None else _default_port(parsed.scheme.lower()),
        path=path,
        host_wildcard=host_wildcard,
        path_wildcard=path_wildcard,
    )


class ScopeMatcher:
    """Matches explicit scheme/host/port/path patterns with deny precedence."""

    def matches(self, pattern: str, target: str) -> bool:
        try:
            expected = parse_asset_pattern(pattern)
            actual = parse_asset_pattern(target)
        except InvalidAssetPattern:
            return False
        if expected.scheme != actual.scheme or expected.port != actual.port:
            return False
        if expected.host_wildcard:
            if actual.host == expected.host or not actual.host.endswith(f".{expected.host}"):
                return False
        elif expected.host != actual.host:
            return False
        if expected.path_wildcard:
            prefix = expected.path.rstrip("/") or "/"
            if prefix == "/":
                return actual.path.startswith("/")
            return actual.path == prefix or actual.path.startswith(f"{prefix}/")
        return expected.path == actual.path

    def matching_scope(self, program: Program, target: str):
        return next((rule for rule in program.scopes if self.matches(rule.asset, target)), None)

    def is_allowed(self, program: Program, target: str) -> bool:
        if not self.matching_scope(program, target):
            return False
        return not any(self.matches(pattern, target) for pattern in program.rules.out_of_scope)


class ScopeGuard:
    """Fail-closed policy gate. No executor may bypass evaluate()."""

    def __init__(self, repository: Repository):
        self.repository = repository
        self.matcher = ScopeMatcher()

    def has_explicit_policy(self, program: Program) -> bool:
        if (
            program.rules.automation_allowed is None
            or program.rules.cross_account_testing is None
            or program.rules.rate_limit_per_minute is None
            or not program.rules.test_account_rules
        ):
            return False
        snapshot = self.repository.get("policy_snapshot", program.policy_snapshot_id or "", ProgramPolicySnapshot)
        return bool(
            snapshot
            and snapshot.human_confirmed
            and snapshot.policy_hash == program.policy_snapshot_hash
            and snapshot.policy_hash == snapshot.content_hash()
            and snapshot.parsed_scope == [rule.asset for rule in program.scopes]
            and snapshot.parsed_out_of_scope == program.rules.out_of_scope
            and snapshot.parsed_rules == program.rules.model_dump(mode="json")
        )

    def is_program_authorized(self, program: Program) -> bool:
        return (
            program.state in {ProgramState.AUTHORIZED, ProgramState.ACTIVE}
            and bool(program.authorization_hash)
            and program.authorization_hash == program.scope_hash()
            and self.has_explicit_policy(program)
        )

    def is_target_allowed(self, program: Program, target: str) -> bool:
        return self.matcher.is_allowed(program, target)

    def is_method_allowed(self, program: Program, target: str, method: str) -> bool:
        rule = self.matcher.matching_scope(program, target)
        return bool(rule and method.upper() in {item.upper() for item in rule.allowed_methods})

    def is_action_allowed(self, program: Program, action: str, target: str | None = None) -> bool:
        normalized = action.upper()
        if normalized in BLOCKED_ACTIONS or normalized not in READ_ACTIONS | SAFE_LOCAL_WRITE_ACTIONS:
            return False
        if program.rules.automation_allowed is not True:
            return False
        if normalized == "READ_OTHER_TEST_ACCOUNT_DATA" and program.rules.cross_account_testing is not True:
            return False
        if target is not None:
            rule = self.matcher.matching_scope(program, target)
            if not rule or normalized not in {item.upper() for item in rule.allowed_actions}:
                return False
        return True

    def is_rate_safe(self, program: Program, proposal: ActionProposal) -> bool:
        rule = self.matcher.matching_scope(program, proposal.target)
        if not rule or program.rules.rate_limit_per_minute is None:
            return False
        if proposal.request_count != 1:
            return False
        limit = min(program.rules.rate_limit_per_minute, rule.max_requests_per_minute)
        return self.repository.count_recent_actions(program.id, proposal.target) + proposal.request_count <= limit

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        try:
            program = self.repository.get_program(proposal.program_id)
            checks = [
                (self.is_program_authorized(program), "PROGRAM_NOT_AUTHORIZED", "Program policy is not explicitly authorized."),
                (self.is_target_allowed(program, proposal.target), "TARGET_OUT_OF_SCOPE", "Target is not explicitly in Scope or is Out of Scope."),
                (self.is_method_allowed(program, proposal.target, proposal.method), "METHOD_NOT_ALLOWED", "HTTP method is not allowed by Scope."),
                (self.is_action_allowed(program, proposal.action, proposal.target), "ACTION_FORBIDDEN", "Action is forbidden or not allowed by policy."),
                (self.is_rate_safe(program, proposal), "RATE_LIMIT_EXCEEDED", "Action exceeds the configured safe request budget."),
            ]
        except Exception:
            decision = PolicyDecision(
                proposal_id=proposal.id, program_id=proposal.program_id, decision=Decision.DENY,
                reason_code="POLICY_ERROR", reason="Policy evaluation failed; request denied.",
                target=proposal.target, method=proposal.method, action=proposal.action,
            )
            try:
                self.repository.save("policy_decision", decision, proposal.program_id, "POLICY_DENY")
            except Exception:
                pass
            return decision
        for passed, code, reason in checks:
            if not passed:
                decision = PolicyDecision(
                    proposal_id=proposal.id, program_id=program.id, decision=Decision.DENY,
                    reason_code=code, reason=reason, target=proposal.target,
                    method=proposal.method, action=proposal.action,
                )
                self.repository.save("policy_decision", decision, program.id, "POLICY_DENY")
                return decision
        decision = PolicyDecision(
            proposal_id=proposal.id, program_id=program.id, decision=Decision.ALLOW,
            reason_code="ALLOW", reason="All Scope Guard checks passed.", target=proposal.target,
            method=proposal.method, action=proposal.action,
        )
        self.repository.save("policy_decision", decision, program.id, "POLICY_ALLOW")
        return decision

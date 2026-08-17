from __future__ import annotations

from urllib.parse import urlsplit

from .domain import ActionProposal, Decision, PolicyDecision, Program, ProgramState
from .storage import Repository

READ_ACTIONS = {"READ", "READ_OWN_DATA", "READ_OTHER_TEST_ACCOUNT_DATA"}
BLOCKED_ACTIONS = {
    "DOS", "STRESS_TEST", "CREDENTIAL_STUFFING", "DELETE_REAL_DATA", "MODIFY_OTHER_USER_DATA",
    "REAL_PAYMENT", "FUNDS_TRANSFER", "LATERAL_MOVEMENT", "PERSISTENCE", "MALWARE", "MASS_DATA_ACCESS",
}


def asset_origin(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme == "lab":
        return f"lab://{parsed.netloc}"
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return None


class ScopeGuard:
    """Fail-closed policy gate. No executor may bypass evaluate()."""

    def __init__(self, repository: Repository):
        self.repository = repository

    def is_program_authorized(self, program: Program) -> bool:
        return (
            program.state in {ProgramState.AUTHORIZED, ProgramState.ACTIVE}
            and bool(program.authorization_hash)
            and program.authorization_hash == program.scope_hash()
        )

    def is_target_allowed(self, program: Program, target: str) -> bool:
        origin = asset_origin(target)
        if origin is None:
            return False
        return any(asset_origin(rule.asset) == origin for rule in program.scopes)

    def is_method_allowed(self, program: Program, target: str, method: str) -> bool:
        origin = asset_origin(target)
        method = method.upper()
        return any(
            asset_origin(rule.asset) == origin and method in {item.upper() for item in rule.allowed_methods}
            for rule in program.scopes
        )

    def is_action_allowed(self, program: Program, action: str, target: str | None = None) -> bool:
        normalized = action.upper()
        if normalized in BLOCKED_ACTIONS or normalized in {
            item.upper() for item in program.rules.prohibited_actions
        } or normalized not in READ_ACTIONS:
            return False
        if not program.rules.automation_allowed:
            return False
        if target is not None:
            origin = asset_origin(target)
            return any(
                asset_origin(rule.asset) == origin
                and normalized in {item.upper() for item in rule.allowed_actions}
                for rule in program.scopes
            )
        return True

    def is_rate_safe(self, program: Program, proposal: ActionProposal) -> bool:
        if proposal.request_count < 1 or proposal.request_count > 1:
            return False
        if proposal.request_count > program.rules.rate_limit_per_minute:
            return False
        return self.repository.count_recent_actions(program.id, proposal.target) + proposal.request_count <= min(
            program.rules.rate_limit_per_minute,
            next(
                (rule.max_requests_per_minute for rule in program.scopes
                 if asset_origin(rule.asset) == asset_origin(proposal.target)),
                0,
            ),
        )

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        program = self.repository.get_program(proposal.program_id)
        checks = [
            (self.is_program_authorized(program), "PROGRAM_NOT_AUTHORIZED", "Program is not human-authorized."),
            (self.is_target_allowed(program, proposal.target), "TARGET_OUT_OF_SCOPE", "Target origin is not explicitly in Scope."),
            (self.is_method_allowed(program, proposal.target, proposal.method), "METHOD_NOT_ALLOWED", "HTTP method is not allowed by Scope."),
            (self.is_action_allowed(program, proposal.action, proposal.target), "ACTION_FORBIDDEN", "Action is forbidden or not allowed by Scope."),
            (self.is_rate_safe(program, proposal), "RATE_LIMIT_EXCEEDED", "Action exceeds the configured safe request budget."),
        ]
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

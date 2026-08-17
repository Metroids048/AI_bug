from __future__ import annotations

from .domain import Program, ProgramState, Rules, ScopeRule, now_utc
from .state import transition_program
from .storage import Repository


def create_program(
    repository: Repository,
    name: str,
    platform: str,
    program_url: str | None,
    asset: str,
    allowed_methods: list[str] | None = None,
) -> Program:
    program = Program(
        name=name,
        platform=platform,
        program_url=program_url,
        scopes=[
            ScopeRule(
                asset=asset,
                allowed_methods=allowed_methods or ["GET"],
                allowed_actions=["READ", "READ_OWN_DATA", "READ_OTHER_TEST_ACCOUNT_DATA"],
            )
        ],
        rules=Rules(),
    )
    repository.save("program", program, program.id, "PROGRAM_CREATED")
    return program


def authorize_program(repository: Repository, program_id: str, scope_hash: str) -> Program:
    program = repository.get_program(program_id)
    if scope_hash != program.scope_hash():
        raise ValueError("Scope hash does not match the current Scope/Rules snapshot.")
    program.state = transition_program(program.state, ProgramState.AUTHORIZED)
    program.authorization_hash = scope_hash
    program.authorized_at = now_utc()
    program.updated_at = now_utc()
    repository.save("program", program, program.id, "PROGRAM_AUTHORIZED")
    return program

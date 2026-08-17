from __future__ import annotations

from .domain import ProgramState, ResearchState

PROGRAM_TRANSITIONS: dict[ProgramState, set[ProgramState]] = {
    ProgramState.DISCOVERED: {ProgramState.REVIEW_REQUIRED},
    ProgramState.REVIEW_REQUIRED: {ProgramState.AUTHORIZED, ProgramState.PAUSED},
    ProgramState.AUTHORIZED: {ProgramState.ACTIVE, ProgramState.PAUSED, ProgramState.COMPLETED},
    ProgramState.ACTIVE: {ProgramState.PAUSED, ProgramState.COMPLETED},
    ProgramState.PAUSED: {ProgramState.REVIEW_REQUIRED, ProgramState.ACTIVE, ProgramState.COMPLETED},
    ProgramState.COMPLETED: set(),
}

RESEARCH_TRANSITIONS: dict[ResearchState, set[ResearchState]] = {
    ResearchState.HYPOTHESIS: {ResearchState.TESTING, ResearchState.LOW_VALUE, ResearchState.OUT_OF_SCOPE},
    ResearchState.TESTING: {ResearchState.OBSERVED, ResearchState.INVALID, ResearchState.OUT_OF_SCOPE, ResearchState.INSUFFICIENT_EVIDENCE},
    ResearchState.OBSERVED: {ResearchState.VALIDATING, ResearchState.INVALID},
    ResearchState.VALIDATING: {ResearchState.REPRODUCED, ResearchState.INVALID, ResearchState.NOT_REPRODUCIBLE, ResearchState.INSUFFICIENT_EVIDENCE},
    ResearchState.REPRODUCED: {ResearchState.ADVERSARIAL_REVIEW, ResearchState.INSUFFICIENT_EVIDENCE},
    ResearchState.ADVERSARIAL_REVIEW: {ResearchState.SUBMISSION_READY, ResearchState.INVALID, ResearchState.LIKELY_DUPLICATE},
    ResearchState.SUBMISSION_READY: {ResearchState.WAITING_HUMAN, ResearchState.SUBMITTED},
    ResearchState.WAITING_HUMAN: {ResearchState.SUBMITTED},
    ResearchState.SUBMITTED: {ResearchState.TRIAGED},
    ResearchState.TRIAGED: set(),
    ResearchState.INVALID: set(),
    ResearchState.LOW_VALUE: set(),
    ResearchState.NOT_REPRODUCIBLE: set(),
    ResearchState.OUT_OF_SCOPE: set(),
    ResearchState.LIKELY_DUPLICATE: set(),
    ResearchState.INSUFFICIENT_EVIDENCE: set(),
}


class InvalidTransition(ValueError):
    pass


def transition_program(current: ProgramState, target: ProgramState) -> ProgramState:
    if target not in PROGRAM_TRANSITIONS[current]:
        raise InvalidTransition(f"Invalid Program transition: {current} -> {target}")
    return target


def transition_research(current: ResearchState, target: ResearchState) -> ResearchState:
    if target not in RESEARCH_TRANSITIONS[current]:
        raise InvalidTransition(f"Invalid Research transition: {current} -> {target}")
    return target

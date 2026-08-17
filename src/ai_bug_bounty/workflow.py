from __future__ import annotations

from dataclasses import dataclass

from .cost import record_usage
from .domain import (
    ActionProposal,
    Decision,
    Evidence,
    Finding,
    Hypothesis,
    PolicyDecision,
    Program,
    ResearchState,
    ValidationResult,
)
from .evidence import EvidenceStore, RedactionError
from .lab import LocalLabExecutor
from .policy import ScopeGuard
from .providers import Provider
from .state import transition_research
from .storage import Repository


@dataclass
class Planner:
    repository: Repository
    provider: Provider

    def plan(self, program: Program, asset: str) -> list[Hypothesis]:
        result = self.provider.plan(program.id, asset)
        record_usage(self.repository, result.provider, result.model, "planner", result.usage, program_id=program.id)
        hypotheses = result.data.hypotheses
        if not 5 <= len(hypotheses) <= 20:
            raise ValueError("Planner must produce between 5 and 20 hypotheses.")
        for hypothesis in hypotheses:
            if hypothesis.program_id != program.id or hypothesis.asset != asset:
                raise ValueError("Planner returned a hypothesis for the wrong program or asset.")
            denominator = max(hypothesis.estimated_cost, 0.1) * max(hypothesis.duplicate_risk, 0.1)
            hypothesis.rank_score = (
                hypothesis.potential_impact * hypothesis.confidence * hypothesis.testability * hypothesis.scope_confidence
            ) / denominator
            self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_CREATED")
        return sorted(hypotheses, key=lambda item: item.rank_score, reverse=True)


class JudgeService:
    def __init__(self, repository: Repository, provider: Provider):
        self.repository = repository
        self.provider = provider

    def review(self, finding: Finding):
        validations = [
            self.repository.get("validation_result", item, ValidationResult)
            for item in finding.validation_result_ids
        ]
        evidences = [self.repository.get("evidence", item, Evidence) for item in finding.evidence_ids]
        decisions = [
            self.repository.get("policy_decision", evidence.scope_decision_id, PolicyDecision)
            for evidence in evidences if evidence
        ]
        scope_passed = len(decisions) == len(evidences) and all(item and item.decision == Decision.ALLOW for item in decisions)
        reproducibility_passed = len(validations) >= 2 and all(item and item.passed for item in validations)
        evidence_passed = len(evidences) >= 2 and all(item and item.complete and item.redacted for item in evidences)
        boundary_passed = bool(finding.security_boundary)
        impact_passed = bool(finding.observed_impact)
        context = {
            "cross_account_private_data": reproducibility_passed and "private" in finding.observed_impact.lower(),
            "expected_behavior": finding.expected_behavior,
            "actual_behavior": finding.actual_behavior,
            "observed_impact": finding.observed_impact,
        }
        skeptic_result = self.provider.skeptic(context)
        record_usage(self.repository, skeptic_result.provider, skeptic_result.model, "skeptic", skeptic_result.usage, finding_id=finding.id)
        skeptic_passed = bool(skeptic_result.data.supports_finding)
        report_quality_passed = bool(finding.title and finding.expected_behavior and finding.actual_behavior)
        passed = all([
            scope_passed, reproducibility_passed, evidence_passed, boundary_passed,
            impact_passed, skeptic_passed, report_quality_passed,
        ])
        from .domain import JudgeResult
        result = JudgeResult(
            finding_id=finding.id, passed=passed, scope_passed=scope_passed,
            reproducibility_passed=reproducibility_passed, evidence_passed=evidence_passed,
            boundary_passed=boundary_passed, impact_passed=impact_passed,
            skeptic_passed=skeptic_passed, report_quality_passed=report_quality_passed,
            counterarguments=skeptic_result.data.counterarguments,
            reason="All deterministic gates and adversarial review passed." if passed else "At least one finding gate failed.",
        )
        self.repository.save("judge_result", result, finding.program_id, "JUDGE_COMPLETED")
        return result


class ResearchOrchestrator:
    def __init__(self, repository: Repository, provider: Provider, executor: LocalLabExecutor | None = None):
        self.repository = repository
        self.provider = provider
        self.guard = ScopeGuard(repository)
        self.evidence = EvidenceStore(repository)
        self.executor = executor or LocalLabExecutor()
        self.judge = JudgeService(repository, provider)

    def run(self, program: Program, hypothesis: Hypothesis) -> Finding:
        if hypothesis.state != ResearchState.HYPOTHESIS:
            raise ValueError("Only a fresh hypothesis can be executed in this MVP.")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.TESTING)
        self.repository.save("hypothesis", hypothesis, program.id, "RESEARCH_STARTED")
        finding = Finding(
            program_id=program.id, hypothesis_id=hypothesis.id, asset=hypothesis.asset,
            category=hypothesis.category, title=f"Potential {hypothesis.category} issue in {hypothesis.feature}",
            security_boundary=hypothesis.expected_security_boundary,
            expected_behavior=hypothesis.expected_security_boundary,
            actual_behavior="", observed_impact="",
            potential_impact="Cross-account access to private resources within the tested boundary.",
        )
        self.repository.save("finding", finding, program.id, "FINDING_CREATED")
        passed_results: list[bool] = []
        for reproduction_number in (1, 2):
            proposal = self._proposal(program, hypothesis)
            self.repository.save("action_proposal", proposal, program.id, "ACTION_PROPOSED")
            decision = self.guard.evaluate(proposal)
            if decision.decision != Decision.ALLOW:
                finding.state = transition_research(finding.state, ResearchState.OUT_OF_SCOPE)
                self.repository.save("finding", finding, program.id, "FINDING_OUT_OF_SCOPE")
                hypothesis.state = transition_research(hypothesis.state, ResearchState.OUT_OF_SCOPE)
                self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_OUT_OF_SCOPE")
                return finding
            observation = self.executor.execute(proposal).model_copy(update={"reproduction_number": reproduction_number})
            self.repository.audit("ACTION_EXECUTED", program.id, program.id, {"target": proposal.target, "request_count": proposal.request_count})
            self.repository.save("observation", observation, program.id, "OBSERVATION_RECORDED")
            cross_account = (
                proposal.account_role == "account_b" and observation.response_status == 200
                and "private_note" in observation.response_body
            )
            observed_impact = (
                "Account B received Account A private document data in the local fixture."
                if cross_account else "No unauthorized private data was observed."
            )
            finding.actual_behavior = observation.actual_behavior
            finding.observed_impact = observed_impact
            try:
                evidence = self.evidence.persist(observation, decision, observed_impact)
            except RedactionError:
                finding.state = transition_research(finding.state, ResearchState.INSUFFICIENT_EVIDENCE)
                self.repository.save("finding", finding, program.id, "EVIDENCE_REJECTED")
                hypothesis.state = transition_research(hypothesis.state, ResearchState.INSUFFICIENT_EVIDENCE)
                self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_INSUFFICIENT_EVIDENCE")
                return finding
            validation = ValidationResult(
                hypothesis_id=hypothesis.id, observation_id=observation.id, evidence_id=evidence.id,
                reproduction_number=reproduction_number, passed=cross_account,
                reason="Unauthorized cross-account private data observed." if cross_account else "Expected denial was observed.",
            )
            self.repository.save("validation_result", validation, program.id, "VALIDATION_RECORDED")
            finding.observation_ids.append(observation.id)
            finding.evidence_ids.append(evidence.id)
            finding.validation_result_ids.append(validation.id)
            passed_results.append(validation.passed)
        finding.state = transition_research(finding.state, ResearchState.OBSERVED)
        self.repository.save("finding", finding, program.id, "FINDING_OBSERVED")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.OBSERVED)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_OBSERVED")
        finding.state = transition_research(finding.state, ResearchState.VALIDATING)
        self.repository.save("finding", finding, program.id, "FINDING_VALIDATING")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.VALIDATING)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_VALIDATING")
        if not all(passed_results):
            finding.state = transition_research(finding.state, ResearchState.INVALID)
            self.repository.save("finding", finding, program.id, "FINDING_INVALID")
            hypothesis.state = transition_research(hypothesis.state, ResearchState.INVALID)
            self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_INVALID")
            return finding
        finding.state = transition_research(finding.state, ResearchState.REPRODUCED)
        self.repository.save("finding", finding, program.id, "FINDING_REPRODUCED")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.REPRODUCED)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_REPRODUCED")
        finding.state = transition_research(finding.state, ResearchState.ADVERSARIAL_REVIEW)
        self.repository.save("finding", finding, program.id, "ADVERSARIAL_REVIEW_STARTED")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.ADVERSARIAL_REVIEW)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_ADVERSARIAL_REVIEW")
        judge = self.judge.review(finding)
        finding.judge_result_id = judge.id
        finding.state = transition_research(
            finding.state, ResearchState.SUBMISSION_READY if judge.passed else ResearchState.INVALID
        )
        self.repository.save("finding", finding, program.id, "FINDING_SUBMISSION_READY" if judge.passed else "FINDING_REJECTED")
        hypothesis.state = transition_research(
            hypothesis.state, ResearchState.SUBMISSION_READY if judge.passed else ResearchState.INVALID
        )
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_COMPLETED")
        return finding

    @staticmethod
    def _proposal(program: Program, hypothesis: Hypothesis) -> ActionProposal:
        if "profile" in hypothesis.feature:
            path = "/api/profile/alice"
        elif "missing" in hypothesis.feature:
            path = "/api/documents/missing"
        else:
            path = "/api/documents/doc-a"
        return ActionProposal(
            program_id=program.id, hypothesis_id=hypothesis.id, target=f"lab://idor{path}",
            method="GET", action="READ_OTHER_TEST_ACCOUNT_DATA", risk=hypothesis.risk,
            reason=hypothesis.validation_plan, account_role="account_b", request_count=1,
            expected_behavior=hypothesis.expected_security_boundary,
        )

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .cost import record_usage
from .domain import (
    ActionProposal,
    Decision,
    Evidence,
    Finding,
    Hypothesis,
    ImpactReviewResult,
    JudgeResult,
    Observation,
    PolicyDecision,
    Program,
    ResearchState,
    SkepticResult,
    TargetProfile,
    ValidationPlan,
    ValidationResult,
    ValidationStep,
)
from .evidence import EvidenceStore, RedactionError
from .lab import LocalLabExecutor
from .policy import ScopeGuard
from .providers import Provider
from .state import transition_research
from .storage import Repository


class PlanContractViolation(ValueError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def resolve_benchmark_operation(method: str, target: str, operations: list[dict[str, Any]]) -> dict[str, Any] | None:
    parsed = urlsplit(target)
    if parsed.scheme != "lab" or parsed.netloc != "benchmark":
        return None
    actual = [segment for segment in parsed.path.split("/") if segment]
    normalized_method = method.upper()
    for operation in operations:
        template = str(operation.get("path", ""))
        expected = [segment for segment in template.split("/") if segment]
        if len(actual) != len(expected):
            continue
        if all(
            (segment[:1] == "{" and segment[-1:] == "}" and actual[index] != "")
            or segment == actual[index]
            for index, segment in enumerate(expected)
        ):
            return operation if str(operation.get("method", "")).upper() == normalized_method else {
                "_method_mismatch": True,
                **operation,
            }
    return None


def validate_benchmark_plan(
    hypothesis: Hypothesis,
    plan: ValidationPlan,
    target_profile: TargetProfile,
) -> str | None:
    """Validate the identity and semantic contract before any target action."""
    if not hypothesis.operation_method or not hypothesis.operation_path:
        return "HYPOTHESIS_OPERATION_MISSING"
    operations = list(target_profile.api_spec.get("operations", []))
    declared = next(
        (
            operation for operation in operations
            if str(operation.get("method", "")).upper() == hypothesis.operation_method.upper()
            and operation.get("path") == hypothesis.operation_path
        ),
        None,
    )
    if declared is None:
        return "HYPOTHESIS_OPERATION_UNKNOWN"
    if plan.hypothesis_id != hypothesis.id:
        return "VALIDATION_PLAN_HYPOTHESIS_MISMATCH"
    phases = {item.phase for item in plan.steps}
    if any(item.phase not in {"CONTROL", "TEST"} for item in plan.steps):
        return "INVALID_PHASE"
    if "CONTROL" not in phases:
        return "MISSING_CONTROL"
    if "TEST" not in phases:
        return "MISSING_TEST"
    resolved: list[dict[str, Any]] = []
    for step in plan.steps:
        parsed = urlsplit(step.target)
        if parsed.scheme != "lab" or parsed.netloc != "benchmark":
            return "STEP_TARGET_OUTSIDE_BENCHMARK"
        operation = resolve_benchmark_operation(step.method, step.target, operations)
        if operation is None:
            return "STEP_OPERATION_UNKNOWN"
        if operation.get("_method_mismatch", False):
            return "STEP_METHOD_MISMATCH"
        resolved.append(operation)
    operation_keys = {(str(item.get("method", "")).upper(), item.get("path")) for item in resolved}
    if len(operation_keys) > 1:
        return "MULTI_OPERATION_PLAN"
    if operation_keys != {(hypothesis.operation_method.upper(), hypothesis.operation_path)}:
        return "SCENARIO_MISMATCH"
    return None


def _provider_context(profile: TargetProfile | None) -> dict[str, Any]:
    if profile is None:
        return {}
    public_operations = [
        {
            key: operation[key]
            for key in ("path", "method", "description")
            if key in operation
        }
        for operation in profile.api_spec.get("operations", [])
    ]
    return {
        "target_profile_id": profile.id,
        "public_brief": profile.public_brief,
        "api_spec": {"operations": public_operations},
        "operations": public_operations,
        "test_accounts": profile.test_accounts,
        "test_resources": {
            name: resource.model_dump(mode="json") for name, resource in profile.test_resources.items()
        },
        "test_inputs": profile.test_inputs,
        "constraints": profile.constraints,
    }


@dataclass
class Planner:
    repository: Repository
    provider: Provider
    experiment_run_id: str | None = None

    def plan(self, program: Program, asset: str, target_profile: TargetProfile | None = None) -> list[Hypothesis]:
        if target_profile:
            self.repository.save("target_profile", target_profile, program.id, "TARGET_PROFILE_CREATED")
        context = _provider_context(target_profile)
        result = self.provider.plan(program.id, asset, context)
        record_usage(
            self.repository, result.provider, result.model, "planner", result.usage,
            result.input_price_per_million, result.output_price_per_million, program_id=program.id,
            experiment_run_id=self.experiment_run_id,
        )
        hypotheses = result.data.hypotheses
        if not 5 <= len(hypotheses) <= 20:
            raise ValueError("Planner must produce between 5 and 20 hypotheses.")
        for hypothesis in hypotheses:
            if hypothesis.program_id != program.id or hypothesis.asset != asset:
                raise ValueError("Planner returned a hypothesis for the wrong program or asset.")
            denominator = max(hypothesis.estimated_cost, 0.1) * max(hypothesis.duplicate_risk, 0.1)
            hypothesis.rank_score = (
                hypothesis.potential_impact * hypothesis.confidence
                * hypothesis.testability * hypothesis.scope_confidence
            ) / denominator
            self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_CREATED")
            plan_result = self.provider.validation_plan(hypothesis, context)
            record_usage(
                self.repository, plan_result.provider, plan_result.model, "validator-planner",
                plan_result.usage, plan_result.input_price_per_million,
                plan_result.output_price_per_million, program_id=program.id,
                experiment_run_id=self.experiment_run_id,
            )
            validation_plan = plan_result.data
            hypothesis.validation_plan_id = validation_plan.id
            self.repository.save("validation_plan", validation_plan, program.id, "VALIDATION_PLAN_CREATED")
            self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_PLAN_LINKED")
        return sorted(hypotheses, key=lambda item: item.rank_score, reverse=True)


class JudgeService:
    def __init__(self, repository: Repository, provider: Provider, skeptic_threshold: float = 0.7, experiment_run_id: str | None = None):
        self.repository = repository
        self.provider = provider
        self.skeptic_threshold = skeptic_threshold
        self.experiment_run_id = experiment_run_id

    def review(self, finding: Finding) -> JudgeResult:
        validations = [
            self.repository.get("validation_result", item, ValidationResult)
            for item in finding.validation_result_ids
        ]
        evidence_ids: list[str] = []
        for validation in validations:
            if validation:
                evidence_ids.extend(validation.evidence_ids or ([validation.evidence_id] if validation.evidence_id else []))
        evidence_ids.extend(finding.evidence_ids)
        evidence_ids = list(dict.fromkeys(evidence_ids))
        evidences = [self.repository.get("evidence", item, Evidence) for item in evidence_ids]
        evidences = [item for item in evidences if item]
        decisions = [
            self.repository.get("policy_decision", evidence.scope_decision_id, PolicyDecision)
            for evidence in evidences
        ]
        scope_passed = len(decisions) == len(evidences) and all(
            item and item.decision == Decision.ALLOW for item in decisions
        )
        reproducibility_passed = len(validations) >= 2 and all(item and item.passed for item in validations)
        evidence_passed = len(evidences) >= 2 and all(item.complete and item.redacted for item in evidences)
        boundary_passed = bool(finding.security_boundary)
        impact_context = {
            "expected_behavior": finding.expected_behavior,
            "actual_behavior": finding.actual_behavior,
            "observed_impact": finding.observed_impact,
            "evidence": [
                {
                    "phase": (self.repository.get("observation", item.observation_id, Observation).phase
                               if self.repository.get("observation", item.observation_id, Observation) else "UNKNOWN"),
                    "request": item.request,
                    "response": item.response,
                    "expected_behavior": item.expected_behavior,
                    "actual_behavior": item.actual_behavior,
                }
                for item in evidences
            ],
        }
        skeptic_result = self.provider.skeptic(impact_context)
        record_usage(
            self.repository, skeptic_result.provider, skeptic_result.model, "skeptic", skeptic_result.usage,
            skeptic_result.input_price_per_million, skeptic_result.output_price_per_million,
            finding_id=finding.id, experiment_run_id=self.experiment_run_id,
        )
        skeptic_data: SkepticResult = skeptic_result.data
        skeptic_passed = (
            skeptic_data.supports_finding
            and skeptic_data.confidence >= self.skeptic_threshold
            and not skeptic_data.counterarguments
        )
        impact_result = self.provider.impact(impact_context)
        record_usage(
            self.repository, impact_result.provider, impact_result.model, "impact-reviewer", impact_result.usage,
            impact_result.input_price_per_million, impact_result.output_price_per_million,
            finding_id=finding.id, experiment_run_id=self.experiment_run_id,
        )
        impact_data: ImpactReviewResult = impact_result.data
        impact_passed = bool(impact_data.passed and impact_data.observed_impact)
        report_quality_passed = bool(finding.title and finding.expected_behavior and finding.actual_behavior)
        passed = all([
            scope_passed, reproducibility_passed, evidence_passed, boundary_passed,
            impact_passed, skeptic_passed, report_quality_passed,
        ])
        result = JudgeResult(
            finding_id=finding.id,
            passed=passed,
            scope_passed=scope_passed,
            reproducibility_passed=reproducibility_passed,
            evidence_passed=evidence_passed,
            boundary_passed=boundary_passed,
            impact_passed=impact_passed,
            skeptic_passed=skeptic_passed,
            report_quality_passed=report_quality_passed,
            impact_reviewer_passed=impact_passed,
            skeptic_confidence=skeptic_data.confidence,
            counterarguments=skeptic_data.counterarguments,
            reason="All deterministic gates and advisory reviews passed." if passed else "At least one final gate failed.",
        )
        self.repository.save("judge_result", result, finding.program_id, "JUDGE_COMPLETED")
        return result


class ResearchOrchestrator:
    def __init__(self, repository: Repository, provider: Provider, executor: LocalLabExecutor | None = None, experiment_run_id: str | None = None):
        self.repository = repository
        self.provider = provider
        self.experiment_run_id = experiment_run_id
        self.guard = ScopeGuard(repository)
        self.evidence = EvidenceStore(repository)
        self.executor = executor or LocalLabExecutor()
        self.judge = JudgeService(repository, provider, experiment_run_id=experiment_run_id)

    def run(self, program: Program, hypothesis: Hypothesis, target_profile: TargetProfile | None = None) -> Finding:
        if hypothesis.state != ResearchState.HYPOTHESIS:
            raise ValueError("Only a fresh hypothesis can be executed in this MVP.")
        plan = self.repository.get("validation_plan", hypothesis.validation_plan_id or "", ValidationPlan)
        if plan is None:
            plan_result = self.provider.validation_plan(hypothesis, _provider_context(target_profile))
            plan = plan_result.data
            self.repository.save("validation_plan", plan, program.id, "VALIDATION_PLAN_CREATED")
        if hypothesis.asset == "lab://benchmark":
            if target_profile is None:
                raise PlanContractViolation("STEP_TARGET_OUTSIDE_BENCHMARK")
            contract_reason = validate_benchmark_plan(hypothesis, plan, target_profile)
            if contract_reason:
                raise PlanContractViolation(contract_reason)
        hypothesis.state = transition_research(hypothesis.state, ResearchState.TESTING)
        self.repository.save("hypothesis", hypothesis, program.id, "RESEARCH_STARTED")
        finding = Finding(
            program_id=program.id,
            hypothesis_id=hypothesis.id,
            asset=hypothesis.asset,
            category=hypothesis.category,
            title=f"Potential {hypothesis.category} issue in {hypothesis.feature}",
            security_boundary=hypothesis.expected_security_boundary,
            expected_behavior=hypothesis.expected_security_boundary,
            actual_behavior="",
            observed_impact="",
            potential_impact="Only the observed local benchmark impact will be considered.",
        )
        self.repository.save("finding", finding, program.id, "FINDING_CREATED")
        reproduction_results: list[bool] = []
        for reproduction_number in (1, 2):
            self.executor.reset()
            observations: list[Observation] = []
            decisions: list[PolicyDecision] = []
            for step in plan.steps:
                proposal = self._proposal(program.id, hypothesis.id, step)
                self.repository.save("action_proposal", proposal, program.id, "ACTION_PROPOSED")
                decision = self.guard.evaluate(proposal)
                decisions.append(decision)
                if decision.decision != Decision.ALLOW:
                    finding.state = transition_research(finding.state, ResearchState.OUT_OF_SCOPE)
                    self.repository.save("finding", finding, program.id, "FINDING_OUT_OF_SCOPE")
                    hypothesis.state = transition_research(hypothesis.state, ResearchState.OUT_OF_SCOPE)
                    self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_OUT_OF_SCOPE")
                    return finding
                observation = self.executor.execute(proposal).model_copy(
                    update={"reproduction_number": reproduction_number}
                )
                self.repository.audit(
                    "ACTION_EXECUTED", program.id, program.id,
                    {"target": proposal.target, "request_count": proposal.request_count},
                )
                self.repository.save("observation", observation, program.id, "OBSERVATION_RECORDED")
                observations.append(observation)
            broken, actual, impact = self._evaluate_plan(plan, observations)
            evidence_ids: list[str] = []
            for observation, decision in zip(observations, decisions, strict=True):
                try:
                    evidence = self.evidence.persist(observation, decision, impact or "No security boundary break observed.")
                except RedactionError:
                    finding.state = transition_research(finding.state, ResearchState.INSUFFICIENT_EVIDENCE)
                    self.repository.save("finding", finding, program.id, "EVIDENCE_REJECTED")
                    hypothesis.state = transition_research(hypothesis.state, ResearchState.INSUFFICIENT_EVIDENCE)
                    self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_INSUFFICIENT_EVIDENCE")
                    return finding
                evidence_ids.append(evidence.id)
                finding.evidence_ids.append(evidence.id)
            validation = ValidationResult(
                hypothesis_id=hypothesis.id,
                observation_id=observations[-1].id,
                evidence_id=evidence_ids[0],
                evidence_ids=evidence_ids,
                validation_plan_id=plan.id,
                reproduction_number=reproduction_number,
                passed=broken,
                reason="The supplied control/test comparison demonstrated a boundary break." if broken else "The supplied control/test comparison did not demonstrate a boundary break.",
            )
            self.repository.save("validation_result", validation, program.id, "VALIDATION_RECORDED")
            finding.validation_result_ids.append(validation.id)
            finding.observation_ids.extend(item.id for item in observations)
            finding.actual_behavior = actual
            finding.observed_impact = impact
            reproduction_results.append(broken)
        finding.state = transition_research(finding.state, ResearchState.OBSERVED)
        self.repository.save("finding", finding, program.id, "FINDING_OBSERVED")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.OBSERVED)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_OBSERVED")
        finding.state = transition_research(finding.state, ResearchState.VALIDATING)
        self.repository.save("finding", finding, program.id, "FINDING_VALIDATING")
        hypothesis.state = transition_research(hypothesis.state, ResearchState.VALIDATING)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_VALIDATING")
        if not all(reproduction_results):
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
        final_state = ResearchState.SUBMISSION_READY if judge.passed else ResearchState.INVALID
        finding.state = transition_research(finding.state, final_state)
        self.repository.save("finding", finding, program.id, "FINDING_SUBMISSION_READY" if judge.passed else "FINDING_REJECTED")
        hypothesis.state = transition_research(hypothesis.state, final_state)
        self.repository.save("hypothesis", hypothesis, program.id, "HYPOTHESIS_COMPLETED")
        return finding

    @staticmethod
    def _proposal(program_id: str, hypothesis_id: str, step: ValidationStep) -> ActionProposal:
        return ActionProposal(
            program_id=program_id,
            hypothesis_id=hypothesis_id,
            target=step.target,
            method=step.method,
            action=step.action,
            risk="LOW",
            reason=step.observation_assertion or step.expected_behavior,
            account_role=step.account_role,
            request_count=1,
            expected_behavior=step.expected_behavior,
            phase=step.phase,
            resource_key=step.resource_key,
            request_query=step.request_query,
            request_payload=step.request_payload,
            expected_status=step.expected_status,
            observation_assertion=step.observation_assertion,
        )

    @staticmethod
    def _evaluate_plan(plan: ValidationPlan, observations: list[Observation]) -> tuple[bool, str, str]:
        controls = [item for item, step in zip(observations, plan.steps, strict=True) if step.phase == "CONTROL"]
        tests = [item for item, step in zip(observations, plan.steps, strict=True) if step.phase == "TEST"]
        control_ok = all(item.response_status < 400 for item in controls)
        protected = any(_protected_data(item.response_body) for item in tests)
        repeated_benefit = any(
            isinstance(item.response_body, dict) and item.response_body.get("redeemed") is True
            for item in tests
        )
        test_statuses = ", ".join(str(item.response_status) for item in tests)
        broken = bool(control_ok and tests and (protected or repeated_benefit))
        actual = f"Control statuses: {[item.response_status for item in controls]}; test statuses: {test_statuses}."
        impact = "Unauthorized or invalid state behavior was observed in the local benchmark." if broken else ""
        return broken, actual, impact


def _protected_data(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    for key, value in body.items():
        key_lower = str(key).lower()
        if any(marker in key_lower for marker in ("private", "secret", "token", "email")):
            return True
        if isinstance(value, dict) and _protected_data(value):
            return True
    return False

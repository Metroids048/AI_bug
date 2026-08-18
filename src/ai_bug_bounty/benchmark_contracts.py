from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .domain import ExperimentBatch, ExperimentCaseResult, ExperimentRun, Observation, TargetProfile, ValidationPlan

BENCHMARK_CONTRACT_VERSION = "M2.6.4"
SEMANTIC_ASSERTION_VERSION = "v2"
FIXTURE_VERSION = "v3"
MODEL_INTERFACE_VERSION = "v1"

SCENARIO_TRUTH: dict[str, bool] = {
    "/api/documents/{id}": True,
    "/api/items/{id}": False,
    "/api/environment": True,
    "/api/environment/details": False,
    "/api/promotions/apply": True,
    "/api/promotions/submit": False,
    "/api/users/{id}": False,
    "/api/records/{id}": False,
    "/api/metadata/{id}": False,
}

SCENARIO_CLASS: dict[str, str] = {
    "/api/documents/{id}": "idor",
    "/api/items/{id}": "idor",
    "/api/environment": "information",
    "/api/environment/details": "information",
    "/api/promotions/apply": "business",
    "/api/promotions/submit": "business",
    "/api/users/{id}": "deceptive_profile",
    "/api/records/{id}": "deceptive_record",
    "/api/metadata/{id}": "deceptive_metadata",
}

PUBLIC_OPERATION_MANIFEST: tuple[dict[str, str], ...] = (
    {"path": "/api/documents/{id}", "method": "GET", "description": "Retrieve a document by identifier."},
    {"path": "/api/items/{id}", "method": "GET", "description": "Retrieve an item by identifier."},
    {"path": "/api/environment", "method": "GET", "description": "Retrieve environment information."},
    {"path": "/api/environment/details", "method": "GET", "description": "Retrieve environment details."},
    {"path": "/api/promotions/apply", "method": "POST", "description": "Apply a promotion to the current account."},
    {"path": "/api/promotions/submit", "method": "POST", "description": "Apply a promotion to the current account."},
    {"path": "/api/users/{id}", "method": "GET", "description": "Retrieve a profile by identifier."},
    {"path": "/api/records/{id}", "method": "GET", "description": "Retrieve a record by identifier."},
    {"path": "/api/metadata/{id}", "method": "GET", "description": "Retrieve metadata associated with a resource."},
)
SCENARIO_MANIFEST = frozenset(SCENARIO_TRUTH)

OperationIdentity = tuple[str, str]


@dataclass(frozen=True)
class BenchmarkOperationCoverageResult:
    expected_identities: tuple[OperationIdentity, ...]
    returned_identities: tuple[OperationIdentity, ...]
    missing: tuple[OperationIdentity, ...]
    duplicate: tuple[OperationIdentity, ...]
    unknown: tuple[OperationIdentity, ...]
    expected_duplicate: tuple[OperationIdentity, ...]
    valid: bool

    @property
    def expected_count(self) -> int:
        return len(self.expected_identities)

    @property
    def returned_count(self) -> int:
        return len(self.returned_identities)


def _operation_identity(method: Any, path: Any) -> OperationIdentity:
    return ("" if method is None else str(method), "" if path is None else str(path))


def validate_benchmark_operation_coverage(
    expected_operations: Iterable[dict[str, Any]], hypotheses: Iterable[Any]
) -> BenchmarkOperationCoverageResult:
    """Compare planner operation identities without evaluating vulnerability semantics."""
    expected = tuple(
        _operation_identity(item.get("method"), item.get("path"))
        for item in expected_operations
    )
    returned = tuple(
        _operation_identity(
            item.get("operation_method"), item.get("operation_path")
        )
        if isinstance(item, dict)
        else _operation_identity(getattr(item, "operation_method", None), getattr(item, "operation_path", None))
        for item in hypotheses
    )
    expected_counts = Counter(expected)
    returned_counts = Counter(returned)
    missing = tuple(
        sorted(
            (identity for identity, count in expected_counts.items() if returned_counts[identity] < count),
            key=lambda identity: (identity[1], identity[0]),
        )
    )
    duplicate = tuple(
        sorted(
            (identity for identity, count in returned_counts.items() if count > 1),
            key=lambda identity: (identity[1], identity[0]),
        )
    )
    unknown = tuple(
        sorted(
            (identity for identity in returned_counts if identity not in expected_counts),
            key=lambda identity: (identity[1], identity[0]),
        )
    )
    expected_duplicate = tuple(
        sorted(
            (identity for identity, count in expected_counts.items() if count > 1),
            key=lambda identity: (identity[1], identity[0]),
        )
    )
    valid = (
        len(expected) == 9
        and len(returned) == 9
        and not missing
        and not duplicate
        and not unknown
        and not expected_duplicate
    )
    return BenchmarkOperationCoverageResult(
        expected_identities=expected,
        returned_identities=returned,
        missing=missing,
        duplicate=duplicate,
        unknown=unknown,
        expected_duplicate=expected_duplicate,
        valid=valid,
    )


@dataclass(frozen=True)
class SemanticEvaluation:
    valid: bool
    vulnerable: bool
    reason_code: str | None = None


@dataclass(frozen=True)
class BatchIntegrityResult:
    valid: bool
    failures: tuple[str, ...]


class BatchIntegrityValidator:
    """Validate one exact batch identity before any metric can pass the Gate."""

    def __init__(
        self,
        batch: ExperimentBatch | None,
        runs: Iterable[ExperimentRun],
        cases: Iterable[ExperimentCaseResult],
        expected_benchmark_version: str | None = None,
    ):
        self.batch = batch
        self.runs = list(runs)
        self.cases = list(cases)
        self.expected_benchmark_version = expected_benchmark_version

    def validate(self) -> BatchIntegrityResult:
        if self.batch is None:
            return BatchIntegrityResult(False, ("missing_batch_id",))

        failures: list[str] = []
        batch = self.batch
        run_ids = list(batch.run_ids)
        listed_ids = set(run_ids)
        all_runs_by_id = {run.id: run for run in self.runs}
        listed_runs = [all_runs_by_id[run_id] for run_id in run_ids if run_id in all_runs_by_id]

        if batch.status.value != "COMPLETED" or batch.completed_at is None:
            failures.append("batch_not_completed")
        if batch.requested_rounds < 3:
            failures.append("insufficient_rounds")
        if len(run_ids) != batch.requested_rounds:
            failures.append("round_count_mismatch")
        if len(run_ids) != len(listed_ids):
            failures.append("duplicate_round")
        if len(listed_runs) != len(run_ids):
            failures.append("foreign_run")
        if {run.id for run in self.runs if run.experiment_batch_id == batch.id} != listed_ids:
            failures.append("foreign_run")
        if self.expected_benchmark_version and batch.benchmark_version != self.expected_benchmark_version:
            failures.append("benchmark_version_mismatch")

        round_numbers: list[int] = []
        for run in listed_runs:
            if run.experiment_batch_id != batch.id or run.program_id != batch.program_id:
                failures.append("foreign_run")
            if run.completed_at is None:
                failures.append("incomplete_run")
            round_numbers.append(run.round_number)
            run_cases = [case for case in self.cases if case.experiment_run_id == run.id]
            if len(run_cases) != 9:
                failures.append("scenario_count_mismatch")
            keys = [case.scenario_key for case in run_cases]
            if len(keys) != len(set(keys)):
                failures.append("duplicate_scenario")
            if set(keys) != SCENARIO_MANIFEST:
                failures.append("missing_scenario")
            if len(run.scenario_order) != 9 or len(set(run.scenario_order)) != 9 or set(run.scenario_order) != SCENARIO_MANIFEST:
                failures.append("missing_scenario")
            for case in run_cases:
                if (
                    case.experiment_batch_id != batch.id
                    or case.experiment_run_id != run.id
                    or case.program_id != batch.program_id
                ):
                    failures.append("foreign_case")

        if len(round_numbers) != len(set(round_numbers)):
            failures.append("duplicate_round")
        if set(round_numbers) != set(range(1, batch.requested_rounds + 1)):
            failures.append("missing_round")

        selected_run_ids = listed_ids
        for case in self.cases:
            if case.experiment_run_id in selected_run_ids and (
                case.experiment_batch_id != batch.id or case.program_id != batch.program_id
            ):
                failures.append("foreign_case")
            if case.experiment_batch_id == batch.id and case.experiment_run_id not in selected_run_ids:
                failures.append("foreign_case")

        unique_failures = tuple(dict.fromkeys(failures))
        return BatchIntegrityResult(not unique_failures, unique_failures)


def _phase_steps(plan: ValidationPlan) -> tuple[list[Any], list[Any]]:
    return (
        [step for step in plan.steps if step.phase == "CONTROL"],
        [step for step in plan.steps if step.phase == "TEST"],
    )


def _resource_id(target: str) -> str:
    return urlsplit(target).path.rstrip("/").rsplit("/", 1)[-1]


def _find_resource(profile: TargetProfile, resource_id: str):
    return next((resource for resource in profile.test_resources.values() if resource.id == resource_id), None)


class ScenarioSemanticContract:
    scenario_key: str
    family: str

    def validate_plan(self, plan: ValidationPlan, profile: TargetProfile) -> str | None:
        controls, tests = _phase_steps(plan)
        if len(controls) != 1:
            return "CONTROL_PHASE_REQUIRED"
        if len(tests) != 1:
            return "TEST_PHASE_REQUIRED"
        if controls[0].target != tests[0].target:
            return "RESOURCE_NOT_IDENTICAL"
        if controls[0].method.upper() != tests[0].method.upper():
            return "OPERATION_NOT_IDENTICAL"
        return None

    def evaluate(self, plan: ValidationPlan, observations: list[Observation]) -> SemanticEvaluation:
        controls, tests = _phase_steps(plan)
        observed_controls = [item for item in observations if item.phase == "CONTROL"]
        observed_tests = [item for item in observations if item.phase == "TEST"]
        if len(controls) != 1 or len(tests) != 1 or len(observed_controls) != 1 or len(observed_tests) != 1:
            return SemanticEvaluation(False, False, "REQUIRED_PHASE_OBSERVATION_MISSING")
        return SemanticEvaluation(True, False)


class AuthorizationScenarioContract(ScenarioSemanticContract):
    family = "authorization"

    def validate_plan(self, plan: ValidationPlan, profile: TargetProfile) -> str | None:
        reason = super().validate_plan(plan, profile)
        if reason:
            return reason
        control, test = _phase_steps(plan)[0][0], _phase_steps(plan)[1][0]
        resource = _find_resource(profile, _resource_id(control.target))
        if resource is None or resource.created_by is None:
            return "CONTROL_RESOURCE_OWNER_UNKNOWN"
        if control.account_role != resource.created_by:
            return "CONTROL_ACCOUNT_NOT_OWNER"
        if test.account_role == resource.created_by:
            return "TEST_ACCOUNT_NOT_DISTINCT"
        return None

    def evaluate(self, plan: ValidationPlan, observations: list[Observation]) -> SemanticEvaluation:
        result = super().evaluate(plan, observations)
        if not result.valid:
            return result
        control = next(item for item in observations if item.phase == "CONTROL")
        test = next(item for item in observations if item.phase == "TEST")
        if control.response_status >= 400:
            return SemanticEvaluation(False, False, "CONTROL_NOT_SUCCESSFUL")
        return SemanticEvaluation(True, test.response_status < 400 and _contains_fields(test.response_body, {"private_note", "owner_email", "session_token"}))


class InformationScenarioContract(ScenarioSemanticContract):
    family = "information"

    def evaluate(self, plan: ValidationPlan, observations: list[Observation]) -> SemanticEvaluation:
        result = super().evaluate(plan, observations)
        if not result.valid:
            return result
        control = next(item for item in observations if item.phase == "CONTROL")
        test = next(item for item in observations if item.phase == "TEST")
        if control.response_status >= 400 or test.response_status >= 400:
            return SemanticEvaluation(True, False)
        hidden_fields = {"internal_email", "internal_host", "credentials", "token", "secret"}
        return SemanticEvaluation(True, _contains_fields(test.response_body, hidden_fields))


class BusinessScenarioContract(ScenarioSemanticContract):
    family = "business"

    def validate_plan(self, plan: ValidationPlan, profile: TargetProfile) -> str | None:
        reason = super().validate_plan(plan, profile)
        if reason:
            return reason
        control, test = _phase_steps(plan)[0][0], _phase_steps(plan)[1][0]
        if control.account_role != test.account_role:
            return "BUSINESS_ACCOUNT_NOT_IDENTICAL"
        if control.request_payload != test.request_payload:
            return "PROMOTION_CODE_NOT_IDENTICAL"
        return None

    def evaluate(self, plan: ValidationPlan, observations: list[Observation]) -> SemanticEvaluation:
        result = super().evaluate(plan, observations)
        if not result.valid:
            return result
        control = next(item for item in observations if item.phase == "CONTROL")
        test = next(item for item in observations if item.phase == "TEST")
        if control.response_status >= 400:
            return SemanticEvaluation(False, False, "CONTROL_NOT_SUCCESSFUL")
        return SemanticEvaluation(True, test.response_status < 400 and test.response_body.get("redeemed") is True)


class GenericScenarioContract(ScenarioSemanticContract):
    family = "generic"


def contract_for(scenario_key: str) -> ScenarioSemanticContract:
    if scenario_key in {"/api/documents/{id}", "/api/items/{id}"}:
        contract = AuthorizationScenarioContract()
    elif scenario_key in {"/api/environment", "/api/environment/details"}:
        contract = InformationScenarioContract()
    elif scenario_key in {"/api/promotions/apply", "/api/promotions/submit"}:
        contract = BusinessScenarioContract()
    else:
        contract = GenericScenarioContract()
    contract.scenario_key = scenario_key
    return contract


def validate_semantic_plan(scenario_key: str, plan: ValidationPlan, profile: TargetProfile) -> str | None:
    return contract_for(scenario_key).validate_plan(plan, profile)


def evaluate_semantic_observations(scenario_key: str, plan: ValidationPlan, observations: list[Observation]) -> SemanticEvaluation:
    return contract_for(scenario_key).evaluate(plan, observations)


def is_semantic_failure(reason_code: str | None) -> bool:
    return reason_code in {
        "CONTROL_PHASE_REQUIRED", "TEST_PHASE_REQUIRED", "RESOURCE_NOT_IDENTICAL",
        "OPERATION_NOT_IDENTICAL", "CONTROL_RESOURCE_OWNER_UNKNOWN", "CONTROL_ACCOUNT_NOT_OWNER",
        "TEST_ACCOUNT_NOT_DISTINCT", "BUSINESS_ACCOUNT_NOT_IDENTICAL", "PROMOTION_CODE_NOT_IDENTICAL",
    }


def _contains_fields(value: Any, fields: set[str]) -> bool:
    if isinstance(value, dict):
        if any(str(key).lower() in fields for key in value):
            return True
        return any(_contains_fields(item, fields) for item in value.values())
    if isinstance(value, list):
        return any(_contains_fields(item, fields) for item in value)
    return False

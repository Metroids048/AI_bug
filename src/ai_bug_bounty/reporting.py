from __future__ import annotations

import json

from .domain import Evidence, Finding, Hypothesis, Observation, ReportDraft, ResearchState, ValidationPlan
from .storage import Repository


class ReportService:
    def __init__(self, repository: Repository):
        self.repository = repository

    def generate(self, finding: Finding) -> ReportDraft:
        if finding.state != ResearchState.SUBMISSION_READY:
            raise ValueError("Only SUBMISSION_READY findings can generate a report.")
        hypothesis = self.repository.get("hypothesis", finding.hypothesis_id, Hypothesis)
        plan = self.repository.get(
            "validation_plan", hypothesis.validation_plan_id if hypothesis else "", ValidationPlan
        )
        if hypothesis is None or plan is None:
            raise ValueError("Finding is missing its hypothesis or validation plan.")
        evidence = [self.repository.get("evidence", item, Evidence) for item in finding.evidence_ids]
        evidence = [item for item in evidence if item]
        lines = [
            f"# {finding.title}", "", "## Summary", finding.actual_behavior, "",
            "## Affected Asset", finding.asset, "", "## Security Boundary", finding.security_boundary, "",
            "## Vulnerability Type", finding.category, "", "## Hypothesis", hypothesis.hypothesis, "",
            "## Steps to Reproduce",
        ]
        for index, step in enumerate(plan.steps, start=1):
            lines.extend([
                f"{index}. **{step.phase}**",
                f"   - Account role: `{step.account_role}`",
                f"   - Method: `{step.method.upper()}`",
                f"   - Target: `{step.target}`",
                f"   - Expected behavior: {step.expected_behavior}",
            ])
        lines.extend([
            "",
            "## Expected Behavior", finding.expected_behavior, "",
            "## Actual Behavior", finding.actual_behavior, "",
            "## Observed Impact", finding.observed_impact, "",
            "## Potential Impact", finding.potential_impact, "",
            "## Evidence (redacted)",
        ])
        for item in evidence:
            observation = self.repository.get("observation", item.observation_id, Observation)
            phase = observation.phase if observation else "UNKNOWN"
            lines.extend([
                f"### Reproduction {item.reproduction_number} ({phase})",
                "```json", json.dumps({"request": item.request, "response": item.response}, indent=2, sort_keys=True), "```",
            ])
        lines.extend(["", "## Scope Confirmation", "ALLOW decisions recorded for every reproduction."])
        draft = ReportDraft(finding_id=finding.id, title=finding.title, markdown="\n".join(lines))
        self.repository.save("report", draft, finding.program_id, "REPORT_DRAFT_CREATED")
        return draft

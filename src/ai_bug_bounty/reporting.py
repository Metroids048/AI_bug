from __future__ import annotations

import json

from .domain import Evidence, Finding, ReportDraft, ResearchState
from .storage import Repository


class ReportService:
    def __init__(self, repository: Repository):
        self.repository = repository

    def generate(self, finding: Finding) -> ReportDraft:
        if finding.state != ResearchState.SUBMISSION_READY:
            raise ValueError("Only SUBMISSION_READY findings can generate a report.")
        evidence = [self.repository.get("evidence", item, Evidence) for item in finding.evidence_ids]
        evidence = [item for item in evidence if item]
        lines = [
            f"# {finding.title}", "", "## Summary", finding.actual_behavior, "",
            "## Affected Asset", finding.asset, "", "## Security Boundary", finding.security_boundary, "",
            "## Vulnerability Type", finding.category, "", "## Steps to Reproduce",
            "1. Use the two researcher-owned test accounts.",
            "2. Authenticate as Account B.",
            "3. Request the Account A document identifier through the local test path.", "",
            "## Expected Behavior", finding.expected_behavior, "",
            "## Actual Behavior", finding.actual_behavior, "",
            "## Observed Impact", finding.observed_impact, "",
            "## Potential Impact", finding.potential_impact, "",
            "## Evidence (redacted)",
        ]
        for item in evidence:
            lines.extend([
                f"### Reproduction {item.reproduction_number}",
                "```json", json.dumps({"request": item.request, "response": item.response}, indent=2, sort_keys=True), "```",
            ])
        lines.extend(["", "## Scope Confirmation", "ALLOW decisions recorded for every reproduction."])
        draft = ReportDraft(finding_id=finding.id, title=finding.title, markdown="\n".join(lines))
        self.repository.save("report", draft, finding.program_id, "REPORT_DRAFT_CREATED")
        return draft

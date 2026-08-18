from __future__ import annotations

import json
from pathlib import Path

import typer

from .domain import Finding, Hypothesis, PlatformResult, PlatformResultStatus, Rules, TargetProfile, now_utc
from .experiments import ExperimentRunner
from .lab import LocalLabExecutor, benchmark_profile
from .programs import authorize_program, create_benchmark_program, create_program
from .providers import provider_factory
from .reporting import ReportService
from .storage import Repository
from .workflow import Planner, ResearchOrchestrator

app = typer.Typer(help="Safe offline AI bug bounty research MVP.")


def repository(db: Path) -> Repository:
    return Repository(db)


def target_profile_for(repo: Repository, program_id: str, asset: str) -> TargetProfile | None:
    profiles = repo.list("target_profile", TargetProfile, program_id)
    if profiles:
        return profiles[0]
    if asset == "lab://benchmark":
        profile = benchmark_profile(program_id)
        repo.save("target_profile", profile, program_id, "TARGET_PROFILE_CREATED")
        return profile
    return None


@app.command("init-db")
def init_db(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    repo.close()
    typer.echo(f"Initialized {db}")


@app.command("program-create")
def program_create(
    name: str = typer.Option(...),
    platform: str = typer.Option(...),
    asset: str = typer.Option(...),
    program_url: str | None = typer.Option(None, "--program-url"),
    raw_policy: str | None = typer.Option(None, "--raw-policy"),
    automation: str = typer.Option("unknown", "--automation", help="unknown, allow, or deny"),
    cross_account: str = typer.Option("unknown", "--cross-account", help="unknown, allow, or deny"),
    rate_limit: int | None = typer.Option(None, "--rate-limit"),
    test_account_rules: str | None = typer.Option(None, "--test-account-rules"),
    out_of_scope: str = typer.Option("", "--out-of-scope", help="Comma-separated explicit patterns"),
    allowed_actions: str = typer.Option("READ", "--allowed-actions", help="Comma-separated actions"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    rules = Rules(
        rate_limit_per_minute=rate_limit,
        automation_allowed=_parse_tristate(automation),
        cross_account_testing=_parse_tristate(cross_account),
        test_account_rules=test_account_rules,
        out_of_scope=[item.strip() for item in out_of_scope.split(",") if item.strip()],
    )
    program = create_program(
        repo, name, platform, program_url, asset, rules=rules,
        allowed_actions=[item.strip() for item in allowed_actions.split(",") if item.strip()],
        raw_policy=raw_policy,
    )
    typer.echo(json.dumps({"program_id": program.id, "scope_hash": program.scope_hash(), "state": program.state.value}))


@app.command("demo-create")
def demo_create(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    program = create_program(
        repo, "Offline IDOR Lab", "local", None, "lab://idor",
        rules=Rules(
            rate_limit_per_minute=30,
            automation_allowed=True,
            cross_account_testing=True,
            test_account_rules="Use only researcher-owned test accounts.",
        ),
        allowed_actions=["READ", "READ_OTHER_TEST_ACCOUNT_DATA"],
    )
    typer.echo(json.dumps({"program_id": program.id, "scope_hash": program.scope_hash(), "state": program.state.value}))


@app.command("benchmark-create")
def benchmark_create(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    program = create_benchmark_program(repo)
    repo.save("target_profile", benchmark_profile(program.id), program.id, "BENCHMARK_PROFILE_CREATED")
    typer.echo(json.dumps({"program_id": program.id, "scope_hash": program.scope_hash(), "state": program.state.value, "asset": "lab://benchmark"}))


@app.command("authorize")
def authorize(
    program_id: str = typer.Argument(...),
    scope_hash: str = typer.Argument(...),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = authorize_program(repo, program_id, scope_hash)
    typer.echo(json.dumps({"program_id": program.id, "state": program.state.value, "authorized_at": program.authorized_at.isoformat()}))


@app.command("plan")
def plan(
    program_id: str = typer.Argument(...),
    asset: str | None = typer.Option(None, "--asset"),
    provider: str | None = typer.Option(None, "--provider"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = repo.get_program(program_id)
    resolved_asset = asset or program.scopes[0].asset
    profile = target_profile_for(repo, program_id, resolved_asset)
    resolved_provider = provider or ("deterministic" if resolved_asset == "lab://idor" else None)
    hypotheses = Planner(repo, provider_factory(resolved_provider)).plan(program, resolved_asset, profile)
    typer.echo(json.dumps([{"id": item.id, "feature": item.feature, "source": item.source, "rank_score": item.rank_score} for item in hypotheses], indent=2))


@app.command("run")
def run(
    program_id: str = typer.Argument(...),
    limit: int = typer.Option(2, min=1, max=20),
    provider: str | None = typer.Option(None, "--provider"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = repo.get_program(program_id)
    profile = target_profile_for(repo, program_id, program.scopes[0].asset)
    resolved_provider = provider or ("deterministic" if program.scopes[0].asset == "lab://idor" else None)
    hypotheses = sorted(repo.list("hypothesis", Hypothesis, program_id), key=lambda item: item.rank_score, reverse=True)
    executor = LocalLabExecutor(lab_name="benchmark" if program.scopes[0].asset == "lab://benchmark" else "idor")
    orchestrator = ResearchOrchestrator(repo, provider_factory(resolved_provider), executor)
    results = [orchestrator.run(program, hypothesis, profile) for hypothesis in hypotheses[:limit]]
    typer.echo(json.dumps([{"finding_id": item.id, "state": item.state.value, "title": item.title} for item in results], indent=2))


@app.command("experiment-run")
def experiment_run(
    program_id: str = typer.Argument(...),
    rounds: int = typer.Option(3, min=1, max=20, help="Independent blind rounds."),
    provider: str | None = typer.Option(None, "--provider"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = repo.get_program(program_id)
    profile = target_profile_for(repo, program_id, program.scopes[0].asset)
    if profile is None or program.scopes[0].asset != "lab://benchmark":
        raise typer.BadParameter("M2.6 requires an authorized lab://benchmark program.")
    runner = ExperimentRunner(repo, provider_factory(provider), LocalLabExecutor(lab_name="benchmark"))
    runs = runner.run(program, profile, rounds=rounds)
    batch_id = runs[0].experiment_batch_id if runs else None
    typer.echo(json.dumps({"batch_id": batch_id, "run_ids": [item.id for item in runs], "summary": repo.experiment_summary(program.id, batch_id=batch_id)}, indent=2))


@app.command("experiment-summary")
def experiment_summary(
    program_id: str | None = typer.Option(None, "--program-id"),
    batch_id: str | None = typer.Option(None, "--batch-id"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    if batch_id is None:
        typer.echo(
            "Unable to load experiment summary: --batch-id is required for Gate evaluation.\n"
            f"Run `abb experiment-list --program-id {program_id or '<PROGRAM_ID>'} --db {db}` to view available batches, "
            "then rerun with --batch-id.",
            err=True,
        )
        raise typer.Exit(code=1)
    repo = repository(db)
    try:
        summary = repo.experiment_summary(program_id, batch_id=batch_id)
    except ValueError as exc:
        program_hint = program_id or "<PROGRAM_ID>"
        typer.echo(
            f"Unable to load experiment summary: {exc}\n"
            f"Run `abb experiment-list --program-id {program_hint} --db {db}` to view available batches, "
            "then rerun with --batch-id.",
            err=True,
        )
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("experiment-list")
def experiment_list(
    program_id: str = typer.Option(..., "--program-id"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    typer.echo(json.dumps([item.model_dump(mode="json") for item in repo.experiment_list(program_id)], indent=2))


@app.command("report")
def report(
    finding_id: str = typer.Argument(...),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
    output_dir: Path = typer.Option(Path("data/reports"), "--output-dir"),
) -> None:
    repo = repository(db)
    finding = repo.get("finding", finding_id, Finding)
    if finding is None:
        raise typer.BadParameter("Unknown finding")
    draft = ReportService(repo).generate(finding)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{draft.id}.md"
    output.write_text(draft.markdown, encoding="utf-8")
    typer.echo(str(output))


@app.command("platform-result")
def platform_result(
    finding_id: str = typer.Argument(...),
    program_id: str = typer.Argument(...),
    submission_id: str = typer.Argument(...),
    status: PlatformResultStatus = typer.Option(..., "--status"),
    reward: float = typer.Option(0.0, "--reward"),
    currency: str = typer.Option("USD", "--currency"),
    severity: str | None = typer.Option(None, "--severity"),
    feedback: str | None = typer.Option(None, "--feedback"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    result = PlatformResult(
        finding_id=finding_id, program_id=program_id, submission_id=submission_id,
        status=status, reward=reward, currency=currency, severity=severity, feedback=feedback,
        submitted_at=now_utc(), triaged_at=now_utc() if status != PlatformResultStatus.SUBMITTED else None,
        paid_at=now_utc() if status == PlatformResultStatus.PAID else None,
    )
    repo.save("platform_result", result, program_id, "PLATFORM_RESULT_RECORDED")
    finding = repo.get("finding", finding_id, Finding)
    if finding:
        finding.platform_result_id = result.id
        repo.save("finding", finding, program_id, "PLATFORM_RESULT_LINKED")
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))


@app.command("roi")
def roi(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    typer.echo(json.dumps(repo.roi_summary(), indent=2))


@app.command("audit-replay")
def audit_replay(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    for event in repo.replay():
        typer.echo(json.dumps(event.model_dump(mode="json"), sort_keys=True))


def _parse_tristate(value: str) -> bool | None:
    normalized = value.lower().strip()
    if normalized in {"allow", "true", "yes"}:
        return True
    if normalized in {"deny", "false", "no"}:
        return False
    if normalized == "unknown":
        return None
    raise typer.BadParameter("Expected allow, deny, or unknown.")


if __name__ == "__main__":
    app()

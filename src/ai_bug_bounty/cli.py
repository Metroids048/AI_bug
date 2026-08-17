from __future__ import annotations

import json
from pathlib import Path

import typer

from .domain import Finding, Hypothesis
from .lab import LocalLabExecutor
from .programs import authorize_program, create_program
from .providers import DeterministicProvider
from .reporting import ReportService
from .storage import Repository
from .workflow import Planner, ResearchOrchestrator

app = typer.Typer(help="Safe offline AI bug bounty research MVP.")


def repository(db: Path) -> Repository:
    return Repository(db)


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
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = create_program(repo, name, platform, program_url, asset)
    typer.echo(json.dumps({"program_id": program.id, "scope_hash": program.scope_hash(), "state": program.state.value}))


@app.command("demo-create")
def demo_create(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    program = create_program(repo, "Offline IDOR Lab", "local", None, "lab://idor")
    typer.echo(json.dumps({"program_id": program.id, "scope_hash": program.scope_hash(), "state": program.state.value}))


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
    asset: str = typer.Option("lab://idor", "--asset"),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = repo.get_program(program_id)
    planner = Planner(repo, DeterministicProvider())
    hypotheses = planner.plan(program, asset)
    typer.echo(json.dumps([{"id": item.id, "feature": item.feature, "rank_score": item.rank_score} for item in hypotheses], indent=2))


@app.command("run")
def run(
    program_id: str = typer.Argument(...),
    limit: int = typer.Option(2, min=1, max=5),
    db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db"),
) -> None:
    repo = repository(db)
    program = repo.get_program(program_id)
    hypotheses = sorted(repo.list("hypothesis", Hypothesis, program_id), key=lambda item: item.rank_score, reverse=True)
    orchestrator = ResearchOrchestrator(repo, DeterministicProvider(), LocalLabExecutor())
    results = [orchestrator.run(program, hypothesis) for hypothesis in hypotheses[:limit]]
    typer.echo(json.dumps([{"finding_id": item.id, "state": item.state.value, "title": item.title} for item in results], indent=2))


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


@app.command("roi")
def roi(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    typer.echo(json.dumps(repo.cost_summary(), indent=2))


@app.command("audit-replay")
def audit_replay(db: Path = typer.Option(Path("data/bugbounty.sqlite3"), "--db")) -> None:
    repo = repository(db)
    for event in repo.replay():
        typer.echo(json.dumps(event.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    app()

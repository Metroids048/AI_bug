# AI Bug Bounty Researcher Offline MVP Implementation Plan

> Implemented in the current workspace from the approved architecture.

**Goal:** Provide a safe, replayable offline IDOR research loop with deterministic tests and an optional OpenAI-compatible model adapter.

**Architecture:** Modular Python CLI, SQLite repositories, fail-closed Scope Guard, in-process FastAPI lab, redacted evidence, deterministic and compatible providers.

**Tech Stack:** Python 3.12, Pydantic, Typer, SQLite, FastAPI, httpx, pytest, Ruff.

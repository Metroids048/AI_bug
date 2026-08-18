from __future__ import annotations

import re
import subprocess
from pathlib import Path


def check_freshness(acceptance: str, current_head: str) -> str | None:
    section_match = re.search(r"^## Verification Result\b.*?(?=^## |\Z)", acceptance, re.MULTILINE | re.DOTALL)
    if section_match is None:
        return "WARNING: ACCEPTANCE.md has no latest Verification Result section."
    commit_match = re.search(r"^- Verification commit:\s*`([0-9a-f]{7,40})`\s*$", section_match.group(0), re.MULTILINE)
    if commit_match is None:
        return "WARNING: ACCEPTANCE.md latest Verification Result has no commit hash."
    recorded_commit = commit_match.group(1)
    if recorded_commit != current_head:
        return f"WARNING: ACCEPTANCE.md may be stale: recorded commit {recorded_commit}, current HEAD {current_head}."
    return None


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    acceptance_path = repository_root / "docs" / "ACCEPTANCE.md"
    try:
        current_head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        warning = check_freshness(acceptance_path.read_text(encoding="utf-8"), current_head)
    except (OSError, subprocess.SubprocessError) as exc:
        warning = f"WARNING: unable to check ACCEPTANCE.md freshness ({type(exc).__name__})."
    if warning:
        print(warning)
    else:
        print(f"ACCEPTANCE.md freshness: matches current HEAD {current_head}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

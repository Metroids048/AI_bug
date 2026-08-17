from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException

from .domain import ActionProposal, Observation


def create_idor_lab() -> FastAPI:
    app = FastAPI(title="Offline IDOR Lab")
    documents = {
        "doc-a": {"id": "doc-a", "owner_id": "alice", "owner_email": "alice@example.test", "private_note": "Account A private document", "session_token": "lab-token-a"},
        "doc-b": {"id": "doc-b", "owner_id": "bob", "owner_email": "bob@example.test", "private_note": "Account B private document", "session_token": "lab-token-b"},
    }

    @app.get("/api/documents/{document_id}")
    async def vulnerable_document(document_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        if document_id not in documents:
            raise HTTPException(status_code=404, detail="document not found")
        if not x_lab_user:
            raise HTTPException(status_code=401, detail="authentication required")
        # Intentionally vulnerable local fixture: it omits the ownership check.
        return documents[document_id]

    @app.get("/api/profile/{user_id}")
    async def secured_profile(user_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        if not x_lab_user:
            raise HTTPException(status_code=401, detail="authentication required")
        if user_id != x_lab_user:
            raise HTTPException(status_code=403, detail="forbidden")
        return {"user_id": user_id, "display_name": user_id.title()}

    return app


class LiveTargetBlocked(RuntimeError):
    pass


class LocalLabExecutor:
    """Only executes lab:// targets through an in-process ASGI transport."""

    def __init__(self, app: FastAPI | None = None):
        self.app = app or create_idor_lab()

    def execute(self, proposal: ActionProposal) -> Observation:
        parsed = urlsplit(proposal.target)
        if parsed.scheme != "lab" or parsed.netloc != "idor":
            raise LiveTargetBlocked("M2 executor refuses every non-lab target.")
        if proposal.method.upper() != "GET":
            raise LiveTargetBlocked("Offline lab only permits the declared read-only GET path.")
        user = {"account_a": "alice", "account_b": "bob"}.get(proposal.account_role)
        if user is None:
            raise LiveTargetBlocked("Unknown test account role.")

        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://offline.lab") as client:
                return await client.get(parsed.path, headers={"X-Lab-User": user})

        response = asyncio.run(request())
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text}
        actual = f"HTTP {response.status_code}; response contains private resource data." if response.status_code == 200 else f"HTTP {response.status_code}; access denied or unavailable."
        return Observation(
            hypothesis_id=proposal.hypothesis_id,
            reproduction_number=1,
            expected_behavior=proposal.expected_behavior,
            actual_behavior=actual,
            response_status=response.status_code,
            response_body=body,
            request_metadata={"method": proposal.method, "target": proposal.target, "account_role": proposal.account_role},
            account_role=proposal.account_role,
            success=response.status_code < 500,
        )

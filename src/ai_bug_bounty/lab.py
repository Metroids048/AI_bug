from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

from .domain import ActionProposal, Observation, TargetProfile, TestResource

ACCOUNT_USERS = {"account_a": "alice", "account_b": "bob"}


def _attach_reset(app: FastAPI, reset) -> FastAPI:
    app.state.reset_fixture = reset
    return app


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
        return documents[document_id]

    @app.get("/api/profile/{user_id}")
    async def secured_profile(user_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        if not x_lab_user:
            raise HTTPException(status_code=401, detail="authentication required")
        if user_id != x_lab_user:
            raise HTTPException(status_code=403, detail="forbidden")
        return {"user_id": user_id, "display_name": user_id.title()}

    return _attach_reset(app, lambda: None)


def create_benchmark_lab() -> FastAPI:
    app = FastAPI(title="Blind Offline Security Benchmark")
    redeemed: set[tuple[str, str]] = set()

    def reset() -> None:
        redeemed.clear()

    def require_user(user: str | None) -> str:
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    @app.get("/api/documents/{document_id}")
    async def vulnerable_idor(document_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        user = require_user(x_lab_user)
        if document_id != "doc-a":
            raise HTTPException(status_code=404, detail="document not found")
        return {"id": document_id, "owner_id": "alice", "owner_email": "alice@example.test", "private_note": "benchmark private note", "viewer": user}

    @app.get("/api/items/{document_id}")
    async def item_document(document_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        user = require_user(x_lab_user)
        if document_id != "item-a":
            raise HTTPException(status_code=404, detail="document not found")
        if user != "alice":
            raise HTTPException(status_code=403, detail="forbidden")
        return {"id": document_id, "owner_id": "alice", "private_note": "benchmark private note", "viewer": user}

    @app.get("/api/users/{user_id}")
    async def user_profile(user_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        require_user(x_lab_user)
        if user_id not in {"alice", "bob"}:
            raise HTTPException(status_code=404, detail="profile not found")
        return {"user_id": user_id, "display_name": user_id.title(), "avatar": "default"}

    @app.get("/api/records/{document_id}")
    async def record_document(document_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        user = require_user(x_lab_user)
        if document_id != "record-a":
            raise HTTPException(status_code=404, detail="document not found")
        return {"id": document_id, "owner_id": "alice", "shared_with": ["bob"], "title": "Project brief", "viewer": user}

    @app.get("/api/metadata/{resource_id}")
    async def metadata(resource_id: str, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        require_user(x_lab_user)
        if resource_id != "item-1":
            raise HTTPException(status_code=404, detail="resource not found")
        return {"id": resource_id, "internal_id": "item-1", "label": "public benchmark item"}

    @app.get("/api/environment")
    async def environment(x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        require_user(x_lab_user)
        return {"environment": "benchmark", "internal_email": "ops@example.test", "internal_host": "db.internal"}

    @app.get("/api/environment/details")
    async def environment_details(x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        require_user(x_lab_user)
        return {"environment": "benchmark"}

    @app.post("/api/promotions/apply")
    async def promotion_apply(request: Request, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        user = require_user(x_lab_user)
        payload = await request.json()
        return {"redeemed": True, "code": payload.get("code", "WELCOME"), "discount": 20, "user": user}

    @app.post("/api/promotions/submit")
    async def promotion_submit(request: Request, x_lab_user: str | None = Header(default=None)) -> dict[str, Any]:
        user = require_user(x_lab_user)
        payload = await request.json()
        code = str(payload.get("code", "WELCOME"))
        key = (user, code)
        if key in redeemed:
            raise HTTPException(status_code=409, detail="reward already redeemed")
        redeemed.add(key)
        return {"redeemed": True, "code": code, "discount": 20, "user": user}

    return _attach_reset(app, reset)


def benchmark_profile(program_id: str) -> TargetProfile:
    operations = [
        {"path": "/api/documents/{id}", "method": "GET", "description": "Retrieve a document by identifier."},
        {"path": "/api/items/{id}", "method": "GET", "description": "Retrieve an item by identifier."},
        {"path": "/api/environment", "method": "GET", "description": "Retrieve environment information."},
        {"path": "/api/environment/details", "method": "GET", "description": "Retrieve environment details."},
        {"path": "/api/promotions/apply", "method": "POST", "description": "Apply a promotion to the current account."},
        {"path": "/api/promotions/submit", "method": "POST", "description": "Apply a promotion to the current account."},
        {"path": "/api/users/{id}", "method": "GET", "description": "Retrieve a profile by identifier."},
        {"path": "/api/records/{id}", "method": "GET", "description": "Retrieve a record by identifier."},
        {"path": "/api/metadata/{id}", "method": "GET", "description": "Retrieve metadata associated with a resource."},
    ]
    return TargetProfile(
        program_id=program_id,
        asset="lab://benchmark",
        category="mixed",
        features=["authorization", "information", "business"],
        public_brief="A local API exposes document, item, environment, promotion, profile, record, and metadata operations. Test accounts are researcher-owned. Determine whether the documented business rules hold.",
        api_spec={"operations": operations},
        test_accounts=["account_a", "account_b"],
        test_resources={
            "document_a": TestResource(id="doc-a", created_by="account_a"),
            "item_a": TestResource(id="item-a", created_by="account_a"),
            "record_a": TestResource(id="record-a"),
            "metadata_a": TestResource(id="item-1"),
        },
        test_inputs={"promotion_code": "WELCOME"},
        constraints=[
            "Use only local lab targets.",
            "Do not infer a vulnerability from a status code alone.",
            "Compare control and test observations.",
            "Document access follows account ownership rules.",
            "Each promotion code may be applied once per account.",
            "Profile and record visibility follows product permissions.",
            "Metadata identifiers do not change account permissions.",
        ],
    )


class LiveTargetBlocked(RuntimeError):
    pass


class LocalLabExecutor:
    """Only executes lab:// targets through an in-process ASGI transport."""

    def __init__(self, app: FastAPI | None = None, lab_name: str = "idor"):
        self.app = app or (create_benchmark_lab() if lab_name == "benchmark" else create_idor_lab())

    def reset(self) -> None:
        reset = getattr(self.app.state, "reset_fixture", None)
        if reset:
            reset()

    def execute(self, proposal: ActionProposal) -> Observation:
        parsed = urlsplit(proposal.target)
        if parsed.scheme != "lab" or parsed.netloc not in {"idor", "benchmark"}:
            raise LiveTargetBlocked("M2.5 executor refuses every non-lab target.")
        if proposal.method.upper() not in {"GET", "POST"}:
            raise LiveTargetBlocked("Offline lab only permits explicit GET or POST test steps.")
        user = ACCOUNT_USERS.get(proposal.account_role)
        if user is None:
            raise LiveTargetBlocked("Unknown test account role.")

        async def request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://offline.lab") as client:
                path = parsed.path
                if proposal.request_query:
                    path = f"{path}?{urlencode(proposal.request_query)}"
                return await client.request(
                    proposal.method.upper(), path,
                    headers={"X-Lab-User": user}, json=proposal.request_payload,
                )

        response = asyncio.run(request())
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text}
        actual = f"HTTP {response.status_code}; response received."
        return Observation(
            hypothesis_id=proposal.hypothesis_id,
            reproduction_number=1,
            expected_behavior=proposal.expected_behavior,
            actual_behavior=actual,
            response_status=response.status_code,
            response_body=body,
            request_metadata={"method": proposal.method, "target": proposal.target, "account_role": proposal.account_role},
            response_headers={key: value for key, value in response.headers.items() if key.lower() not in {"set-cookie"}},
            phase=proposal.phase,
            resource_key=proposal.resource_key,
            account_role=proposal.account_role,
            success=response.status_code < 500,
        )

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sentinel_guard.audit_log import append_audit_log
from sentinel_guard.orchestrator import run_guardrail_pipeline
from sentinel_guard.pii_engine import unmask_text

app = FastAPI(
    title="LLM Guardrail",
    description="Six-gate prompt security pipeline for LLM inputs.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Fails closed: blocks every request unless it carries the configured key."""
    expected_key = os.environ.get("GUARDRAIL_API_KEY")

    if not expected_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
        )


class CheckRequest(BaseModel):
    prompt: str


class CheckResponse(BaseModel):
    is_allowed: bool
    processed_prompt: str
    rejection_reason: str | None
    audit_flags: list[str]
    anonymization_vault: dict[str, str]


class RestoreRequest(BaseModel):
    text: str
    vault: dict[str, str]


class RestoreResponse(BaseModel):
    restored_text: str


@app.post(
    "/check",
    response_model=CheckResponse,
    dependencies=[Depends(require_api_key)],
)
def check_prompt(request: CheckRequest) -> CheckResponse:
    """Runs one prompt through the six-gate pipeline and returns the verdict."""
    result = run_guardrail_pipeline(request.prompt)

    append_audit_log(
        processed_prompt=result.processed_prompt,
        is_allowed=result.is_allowed,
        rejection_reason=result.rejection_reason,
        audit_flags=result.audit_flags,
    )

    return CheckResponse(
        is_allowed=result.is_allowed,
        processed_prompt=result.processed_prompt,
        rejection_reason=result.rejection_reason,
        audit_flags=result.audit_flags,
        anonymization_vault=result.anonymization_vault,
    )


@app.post(
    "/restore",
    response_model=RestoreResponse,
    dependencies=[Depends(require_api_key)],
)
def restore_text(request: RestoreRequest) -> RestoreResponse:
    """Replaces PII placeholder tokens in an LLM's reply with their real values."""
    return RestoreResponse(
        restored_text=unmask_text(request.text, request.vault)
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    """Lets a client confirm the API is reachable before sending real traffic."""
    return {"status": "ok"}

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from sentinel_guard.orchestrator import run_guardrail_pipeline

app = FastAPI(
    title="LLM Guardrail",
    description="Six-gate prompt security pipeline for LLM inputs.",
)


class CheckRequest(BaseModel):
    prompt: str


class CheckResponse(BaseModel):
    is_allowed: bool
    processed_prompt: str
    rejection_reason: str | None
    audit_flags: list[str]


@app.post("/check", response_model=CheckResponse)
def check_prompt(request: CheckRequest) -> CheckResponse:
    """Runs one prompt through the six-gate pipeline and returns the verdict."""
    result = run_guardrail_pipeline(request.prompt)

    return CheckResponse(
        is_allowed=result.is_allowed,
        processed_prompt=result.processed_prompt,
        rejection_reason=result.rejection_reason,
        audit_flags=result.audit_flags,
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    """Lets a client confirm the API is reachable before sending real traffic."""
    return {"status": "ok"}

"""
The HTTP surface.

Application-level LLM guardrails are not a substitute for boring web security,
so this file also shows the boring parts: input size limits, rate limiting,
no stack traces in responses, and a start-up integrity gate.

Run:  make serve      ->  http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinelrag.audit import log_event, verify_chain
from sentinelrag.config import settings
from sentinelrag.rag.answerer import answer
from sentinelrag.vectorstore.model_gate import ModelIntegrityError, load_embedding_model
from sentinelrag.vectorstore.store import stats

app = FastAPI(
    title="Sentinel-RAG",
    version="0.1.0",
    description="A prompt-injection-resistant RAG service",
)

# --- simple in-memory rate limit (use Redis in real production) -------------
_WINDOW_SECONDS = 60
_MAX_REQUESTS = 20
_hits: dict[str, deque] = defaultdict(deque)


def _rate_limited(client_ip: str) -> bool:
    now = time.time()
    bucket = _hits[client_ip]
    while bucket and now - bucket[0] > _WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _MAX_REQUESTS:
        return True
    bucket.append(now)
    return False


class AskRequest(BaseModel):
    # CONTROL: bound the input. Unbounded prompts are a cost-DoS vector and give
    # an attacker room to bury a payload in 200 KB of filler.
    question: str = Field(min_length=1, max_length=4000)
    k: int = Field(default=5, ge=1, le=10)
    min_trust: str = Field(default="unclassified",
                           pattern="^(unclassified|untrusted|internal|trusted)$")


class AskResponse(BaseModel):
    answer: str
    sources: list[str]
    blocked: bool
    security: dict
    latency_ms: int


@app.on_event("startup")
def startup() -> None:
    """Fail fast: verify model integrity BEFORE serving a single request."""
    try:
        load_embedding_model()
    except ModelIntegrityError as exc:
        # In production you want the process to die here rather than serve with
        # an unverified model. Keep the message actionable.
        raise SystemExit(f"\nSTARTUP ABORTED -- model integrity check failed:\n{exc}\n")
    intact, index = verify_chain()
    if not intact:
        print(f"[!] WARNING: audit log chain broken at record {index}")
    log_event("service_start", model=settings.gemini_model, store=stats())


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    """Never leak internals. Stack traces in HTTP responses are a real leak class."""
    log_event("unhandled_error", path=request.url.path, error=str(exc)[:300])
    return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.get("/health")
def health() -> dict:
    intact, _ = verify_chain()
    return {"status": "ok", "store": stats(), "audit_log_intact": intact}


@app.post("/ask", response_model=AskResponse)
def ask(request: Request, body: AskRequest) -> AskResponse:
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    result = answer(body.question, k=body.k, min_trust=body.min_trust)
    return AskResponse(
        answer=result.answer,
        sources=result.sources,
        blocked=result.blocked,
        security=result.security,
        latency_ms=result.latency_ms,
    )

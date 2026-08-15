"""
The orchestrator. This is the file to read if you only read one.

    question
       |
       v
  [1] input guard ............ direct prompt injection / jailbreak
       |
       v
  [2] retrieve ............... trust-weighted vector search
       |
       v
  [3] chunk guard ............ indirect prompt injection (runtime re-check)
       |
       v
  [4] build prompt ........... spotlighting + datamarking + canary
       |
       v
  [5] Gemini
       |
       v
  [6] output guard ........... canary leak, PII, secrets, exfil links
       |
       v
   answer + security report

Note there is no single "the security check". Each stage assumes the previous
one failed. That is what defence in depth actually means in code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from sentinelrag.audit import log_event, sha256_text
from sentinelrag.guardrails.input_guard import Action, inspect, neutralize
from sentinelrag.guardrails.output_guard import inspect_output
from sentinelrag.llm.gemini_client import LLMError, generate
from sentinelrag.llm.prompts import build_system_prompt, build_user_prompt, new_data_marker
from sentinelrag.vectorstore.store import search

REFUSAL = (
    "I can't process that request. It looks like an attempt to change my "
    "instructions or extract my configuration. If this was a genuine question, "
    "please rephrase it."
)


@dataclass
class AnswerResult:
    answer: str
    sources: list[str] = field(default_factory=list)
    blocked: bool = False
    security: dict = field(default_factory=dict)
    latency_ms: int = 0


def answer(question: str, *, k: int = 5, min_trust: str = "unclassified") -> AnswerResult:
    started = time.time()
    report: dict = {"stages": {}}

    # --- [1] direct injection ---------------------------------------------
    user_verdict = inspect(question, source="user")
    report["stages"]["input_guard"] = {
        "action": user_verdict.action.value,
        "score": user_verdict.score,
        "signals": user_verdict.signals,
    }
    if user_verdict.is_blocked:
        log_event("request_blocked", stage="input_guard", score=user_verdict.score,
                  question_sha256=sha256_text(question))
        return AnswerResult(answer=REFUSAL, blocked=True, security=report,
                            latency_ms=int((time.time() - started) * 1000))

    # --- [2] retrieval -----------------------------------------------------
    chunks = search(question, k=k, min_trust=min_trust)
    report["stages"]["retrieval"] = {
        "retrieved": len(chunks),
        "trust_mix": {c.trust: 1 for c in chunks} and
                     {t: sum(c.trust == t for c in chunks) for t in {c.trust for c in chunks}},
    }

    # --- [3] indirect injection -------------------------------------------
    prepared: list[dict] = []
    dropped, flagged = 0, 0
    for chunk in chunks:
        chunk_verdict = inspect(chunk.text, source=f"retrieved:{chunk.source}", use_judge=False)
        if chunk_verdict.is_blocked:
            dropped += 1
            log_event("chunk_dropped", source=chunk.source, score=chunk_verdict.score,
                      signals=chunk_verdict.signals)
            continue
        is_flagged = chunk_verdict.action is Action.FLAG or chunk.flagged
        if is_flagged:
            flagged += 1
        prepared.append({
            "text": neutralize(chunk.text) if is_flagged else chunk.text,
            "source": chunk.source,
            "trust": chunk.trust,
            "flagged": is_flagged,
        })
    report["stages"]["chunk_guard"] = {"dropped": dropped, "flagged": flagged,
                                       "passed": len(prepared)}

    if not prepared:
        return AnswerResult(
            answer="I don't have anything in the knowledge base for that "
                   "(or everything relevant was quarantined by the security filter).",
            security=report, latency_ms=int((time.time() - started) * 1000),
        )

    # --- [4] prompt construction ------------------------------------------
    marker = new_data_marker()
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(question, prepared, marker)
    report["stages"]["prompt"] = {"data_marker": marker, "documents": len(prepared)}

    # --- [5] generation ----------------------------------------------------
    try:
        raw_answer = generate(system=system_prompt, user=user_prompt, max_output_tokens=900)
    except LLMError as exc:
        return AnswerResult(answer=f"The model is unavailable right now ({exc}).",
                            security=report, latency_ms=int((time.time() - started) * 1000))

    # --- [6] output guard --------------------------------------------------
    output_verdict = inspect_output(raw_answer)
    report["stages"]["output_guard"] = {
        "findings": output_verdict.findings,
        "blocked": output_verdict.blocked,
        "modified": output_verdict.text != raw_answer,
    }

    result = AnswerResult(
        answer=output_verdict.text,
        sources=sorted({c["source"] for c in prepared}),
        blocked=output_verdict.blocked,
        security=report,
        latency_ms=int((time.time() - started) * 1000),
    )

    log_event("request_completed", blocked=result.blocked, sources=len(result.sources),
              latency_ms=result.latency_ms,
              findings=output_verdict.findings, input_score=user_verdict.score)
    return result

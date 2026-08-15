"""
The one place that talks to Gemini.

Wrapping the SDK in a single module buys you a lot:
  * the API key is read from config once and never printed or logged
  * every call is audited (model, token counts, latency -- never the raw prompt)
  * we can enforce a hard output-token cap, which limits how much data a
    successful exfiltration attempt can carry out in one response
  * retries and quota errors are handled in one place (free tier is ~15 RPM)

Model IDs come from .env. Note that on Gemini 3.x, temperature/top_p/top_k are
deprecated -- reasoning effort is controlled with `thinking_level` instead.
"""

from __future__ import annotations

import json
import re
import time
from functools import lru_cache

from sentinelrag.audit import log_event
from sentinelrag.config import settings


class LLMError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _client():
    from google import genai

    if not settings.gemini_api_key:
        raise LLMError("GEMINI_API_KEY is not set. Copy .env.example to .env and fill it in.")
    return genai.Client(api_key=settings.gemini_api_key)


def generate(
    *,
    system: str,
    user: str,
    model: str | None = None,
    max_output_tokens: int = 1024,
    thinking_level: str = "low",
    tools: list | None = None,
) -> str:
    """Plain text generation. Returns the model's text output."""
    from google.genai import types

    model = model or settings.gemini_model
    config = types.GenerateContentConfig(
        system_instruction=system,
        max_output_tokens=max_output_tokens,
        thinking_config=types.ThinkingConfig(thinking_level=thinking_level),
        # Keep Google's own safety filters on. They are a free extra layer;
        # they are NOT a substitute for your own guardrails.
        tools=tools or None,
    )

    started = time.time()
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = _client().models.generate_content(
                model=model, contents=user, config=config
            )
            log_event(
                "llm_call",
                model=model,
                latency_ms=int((time.time() - started) * 1000),
                input_chars=len(user),
                output_chars=len(response.text or ""),
                attempt=attempt,
            )
            return response.text or ""
        except Exception as exc:  # noqa: BLE001 -- we re-raise below
            last_error = exc
            message = str(exc).lower()
            if "429" in message or "quota" in message or "resource_exhausted" in message:
                time.sleep(2 ** attempt * 5)   # free tier: back off hard
                continue
            if "503" in message or "500" in message:
                time.sleep(2 ** attempt)
                continue
            break

    log_event("llm_error", model=model, error=str(last_error)[:300])
    raise LLMError(f"Gemini call failed: {last_error}")


_JSON_RX = re.compile(r"\{.*\}", re.DOTALL)


def generate_json(*, system: str, user: str, model: str | None = None) -> dict:
    """
    Generation where we need a machine-readable answer (the security judge).

    We ask for JSON, then parse defensively: even a model told "JSON only"
    sometimes wraps it in ```json fences, and an injected payload may try to
    make it emit prose. If we cannot parse, we return {} -- and the caller
    treats "no verdict" as "no evidence", never as "safe by default".
    """
    raw = generate(system=system, user=user, model=model, max_output_tokens=256,
                   thinking_level="minimal")
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = _JSON_RX.search(cleaned)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    log_event("llm_json_parse_failed", preview=cleaned[:200])
    return {}

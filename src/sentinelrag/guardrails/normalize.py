"""
De-obfuscation.

Every naive prompt-injection filter dies the same way: the attacker doesn't
write "ignore previous instructions", they write

    "ign\u200bore previous instructions"          (zero-width space inside a word)
    "ıgnore prevıous ınstructions"                 (Turkish dotless i homoglyph)
    "aWdub3JlIHByZXZpb3Vz..."                      (base64)
    "erongi suoiverp snoitcurtsni"                 (reversed)
    "1gn0r3 pr3v10u5"                              (leetspeak)

The model still understands all of these. Your regex does not.

So: normalise FIRST, detect SECOND. We keep the original text for the user and
run detection on the normalised variants. `expand_variants` returns every form
worth scanning -- if ANY variant trips a detector, the input is suspicious.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Characters that are invisible but survive copy-paste. Classic filter bypass.
INVISIBLE = dict.fromkeys(
    [0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060,
     0xFEFF, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E]
)

# "Tag" characters (U+E0000 block) can encode invisible ASCII inside text --
# used in real "invisible prompt injection" research.
TAG_BLOCK = range(0xE0000, 0xE0080)

HOMOGLYPHS = str.maketrans({
    "\u0131": "i", "\u0456": "i", "\u04CF": "i",   # dotless i, Cyrillic i
    "\u0430": "a", "\u0435": "e", "\u043E": "o",   # Cyrillic a/e/o
    "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0455": "s", "\u0443": "y", "\u04BB": "h",
    "\uFF49": "i", "\uFF41": "a",                   # fullwidth
})

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_B64_RE = re.compile(r"[A-Za-z0-9+/=]{24,}")


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi-override and tag characters."""
    out = text.translate(INVISIBLE)
    return "".join(ch for ch in out if ord(ch) not in TAG_BLOCK)


def canonical(text: str) -> str:
    """
    The one form everything else is derived from:
    NFKC-normalised, homoglyphs folded, invisibles removed, whitespace collapsed.
    """
    out = unicodedata.normalize("NFKC", text)
    out = strip_invisible(out)
    out = out.translate(HOMOGLYPHS)
    out = re.sub(r"[ \t\u00A0]+", " ", out)
    return out.strip()


def decode_base64_blobs(text: str) -> list[str]:
    """Return anything that decodes cleanly from base64 -- attackers hide payloads there."""
    found = []
    for match in _B64_RE.findall(text):
        try:
            decoded = base64.b64decode(match + "=" * (-len(match) % 4), validate=True)
            text_out = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        # Only keep it if it looks like natural language, not random bytes.
        printable = sum(ch.isprintable() for ch in text_out) / max(len(text_out), 1)
        if len(text_out) >= 12 and printable > 0.9:
            found.append(text_out)
    return found


def expand_variants(text: str) -> list[str]:
    """All the forms a detector should look at. Cheap: pure string ops."""
    base = canonical(text)
    variants = [base, base.lower(), base.lower().translate(LEET), base[::-1].lower()]
    variants.extend(canonical(blob).lower() for blob in decode_base64_blobs(base))
    # De-duplicate while preserving order.
    seen, out = set(), []
    for variant in variants:
        if variant and variant not in seen:
            seen.add(variant)
            out.append(variant)
    return out


def obfuscation_signals(text: str) -> list[str]:
    """
    Obfuscation is itself a signal. Normal users do not put bidi overrides in
    their questions. Presence of these raises the score even if no keyword hits.
    """
    signals = []
    if any(ord(ch) in INVISIBLE for ch in text):
        signals.append("invisible_unicode")
    if any(ord(ch) in TAG_BLOCK for ch in text):
        signals.append("unicode_tag_characters")
    if text != unicodedata.normalize("NFKC", text):
        signals.append("non_nfkc_input")
    if any(ch in HOMOGLYPHS.keys() for ch in map(ord, text)):
        signals.append("homoglyphs")
    if decode_base64_blobs(text):
        signals.append("embedded_base64")
    return signals

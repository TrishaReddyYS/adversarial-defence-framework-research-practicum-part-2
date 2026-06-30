"""Prompt-injection pattern detection.

Detectors for the common prompt-injection vectors: direct injection (instruction override),
context manipulation / hijacking, separator manipulation, and obfuscated payloads (base64 /
encoded instructions). Each detector returns scored signals so the sanitiser can combine them.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from adf.common.datasets import AdversarialKind


@dataclass
class Signal:
    """One injection indicator found in a prompt."""

    kind: AdversarialKind
    pattern: str
    score: float          # 0..1 contribution to the injection risk
    span: tuple[int, int] = (0, 0)
    note: str = ""


# Direct instruction-override phrases (case-insensitive).
_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.I), 0.9,
     "instruction override"),
    (re.compile(r"\bdisregard\s+(the\s+)?(above|previous|prior|safety|secure)", re.I), 0.85,
     "disregard directive"),
    (re.compile(r"\bforget\s+(everything|about\s+safety|the\s+rules)", re.I), 0.8,
     "forget directive"),
    (re.compile(r"\b(do\s+not|don't)\s+(validate|saniti[sz]e|escape|check)\b", re.I), 0.75,
     "disable safeguard"),
    (re.compile(r"\b(insert|concatenate|build).{0,40}\b(raw|directly|without\s+escap)", re.I), 0.7,
     "unsafe construction request"),
    (re.compile(r"\bhard-?code\b.{0,30}\b(password|secret|api[\s_-]?key|token|credential)", re.I),
     0.8, "hard-coded secret request"),
    (re.compile(r"\bpassword(s)?\b.{0,30}\b(plain[\s-]*text|cleartext|unencrypted|in\s+the\s+clear)\b",
                re.I), 0.7, "plaintext password request"),
    (re.compile(r"\b(disable|turn\s+off|skip|bypass|remove|no)\b.{0,25}"
                r"\b(validat\w+|saniti[sz]\w+|escap\w+|authentication|input\s+check|csrf|ssl|tls)\b",
                re.I), 0.7, "disable safeguard request"),
    (re.compile(r"\b(eval|exec)\b.{0,20}\b(user|input|request|param|argument)", re.I), 0.6,
     "executes untrusted input"),
    (re.compile(r"\b(md5|sha-?1)\b.{0,25}\bpassword", re.I), 0.6, "weak password hashing"),
    (re.compile(r"\bsystem\s*prompt\b|\byou\s+are\s+now\b|\bact\s+as\b", re.I), 0.5,
     "role reassignment"),
]

# Separator / delimiter manipulation often used to break out of the intended context.
_SEPARATOR_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"-{3,}|={3,}|#{3,}"), 0.4, "delimiter block"),
    (re.compile(r"```.*?```", re.S), 0.2, "fenced block"),
    (re.compile(r"\[/?(INST|SYS|SYSTEM)\]", re.I), 0.7, "chat-template token"),
    (re.compile(r"<\|.*?\|>"), 0.6, "special model token"),
]

# Indirect injection: deferring to external/retrieved content that carries the payload.
_INDIRECT_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"\b(follow|apply|obey|use|reuse)\b.{0,40}\b(readme|docs?|file|url|link|comment|"
                r"helper|utils?|guide)\b", re.I), 0.6, "defers to external source"),
    (re.compile(r"\bnote:\s*that\b", re.I), 0.4, "embedded side-note instruction"),
]

# Obfuscation markers.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_ENCODED_HINT_RE = re.compile(r"\b(decode|base64|rot13|hex|unescape)\b", re.I)


def _decode_base64(token: str) -> str | None:
    # Re-pad to a multiple of 4 in case surrounding punctuation trimmed the '=' padding.
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Only treat as meaningful if it decodes to mostly printable text.
    printable = sum(c.isprintable() for c in text)
    if text and printable / len(text) > 0.8:
        return text
    return None


def detect_signals(prompt: str) -> list[Signal]:
    """Return all injection signals found in the prompt."""
    signals: list[Signal] = []

    for rx, score, note in _OVERRIDE_PATTERNS:
        for m in rx.finditer(prompt):
            signals.append(Signal(AdversarialKind.DIRECT, rx.pattern, score, m.span(), note))

    for rx, score, note in _SEPARATOR_PATTERNS:
        for m in rx.finditer(prompt):
            signals.append(Signal(AdversarialKind.DIRECT, rx.pattern, score, m.span(), note))

    for rx, score, note in _INDIRECT_PATTERNS:
        for m in rx.finditer(prompt):
            signals.append(Signal(AdversarialKind.INDIRECT, rx.pattern, score, m.span(), note))

    # Obfuscation: an encoded blob whose decoding reveals a hidden instruction.
    encoded_hint = bool(_ENCODED_HINT_RE.search(prompt))
    for m in _BASE64_RE.finditer(prompt):
        decoded = _decode_base64(m.group(0))
        if decoded is None:
            continue
        score = 0.85 if (encoded_hint or _looks_instructional(decoded)) else 0.5
        signals.append(
            Signal(AdversarialKind.OBFUSCATED, "base64", score, m.span(),
                   f"decoded: {decoded[:60]!r}")
        )
    return signals


_INSTRUCTIONAL_RE = re.compile(
    r"\b(ignore|disable|bypass|skip|disregard|without|raw|exec|eval|delete|drop)\b", re.I
)


def _looks_instructional(text: str) -> bool:
    return bool(_INSTRUCTIONAL_RE.search(text))

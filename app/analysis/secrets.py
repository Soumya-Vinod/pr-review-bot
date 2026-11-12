"""Detects likely committed secrets (API keys, tokens, private keys) in added lines.

Findings are reported masked (first 4 characters + "****"), never with the full value.
redact_patch() strips secret-bearing lines from a patch before it leaves the process
(e.g. to the LLM).
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from app.analysis.rules import Finding, PRFile

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
REDACTED = "[REDACTED]"
MAX_REPORTED = 50

PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
PRIVATE_KEY_END = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")

# (kind, pattern, group holding the secret value)
PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("AWS access key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    ("GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"), 1),
    ("GitHub token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})\b"), 1),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"), 1),
    ("Private key", PRIVATE_KEY_BEGIN, 0),
    (
        "Hardcoded credential",
        re.compile(
            r"(?i)[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d)[\w.-]*[\"']?"
            r"\s*[:=]\s*([\"'])([^\"'\s]{8,})\1"
        ),
        2,
    ),
)


@dataclass(frozen=True, slots=True)
class SecretFinding:
    filename: str
    line: int | None  # line number in the new file
    kind: str
    masked: str


def mask(value: str) -> str:
    """First 4 characters followed by ****; never the full value."""
    return value[:4] + "****"


def iter_added_lines(patch: str) -> Iterator[tuple[int | None, str]]:
    """Yield (new-file line number, text) for every added line of a unified-diff patch."""
    new_line: int | None = None
    for raw in patch.splitlines():
        header = HUNK_RE.match(raw)
        if header:
            new_line = int(header.group(1))
            continue
        if raw.startswith("+"):
            yield new_line, raw[1:]
            new_line = new_line + 1 if new_line is not None else None
        elif raw.startswith("-") or raw.startswith("\\"):
            continue  # removed line or "\ No newline at end of file"
        elif new_line is not None:
            new_line += 1  # context line


def _matches(text: str) -> Iterator[tuple[str, str]]:
    for kind, pattern, group in PATTERNS:
        for match in pattern.finditer(text):
            yield kind, match.group(group)


def scan_patch(filename: str, patch: str | None) -> list[SecretFinding]:
    if not patch:
        return []
    findings: list[SecretFinding] = []
    for line_no, text in iter_added_lines(patch):
        seen: set[str] = set()
        for kind, value in _matches(text):
            if kind in seen:
                continue
            seen.add(kind)
            findings.append(SecretFinding(filename, line_no, kind, mask(value)))
    return findings


def scan_files(files: Iterable[PRFile]) -> list[SecretFinding]:
    return [finding for f in files for finding in scan_patch(f.filename, f.patch)]


def has_secret(text: str) -> bool:
    return any(True for _ in _matches(text))


def redact_patch(patch: str) -> str:
    """Replace every diff line that looks like it holds a secret with [REDACTED].

    Removed and context lines are redacted too (they would leak just the same), and
    everything between a PRIVATE KEY BEGIN/END pair is redacted, not only the header.
    """
    out: list[str] = []
    in_key = False
    for raw in patch.splitlines():
        if HUNK_RE.match(raw) or raw.startswith("\\"):
            out.append(raw)
            continue
        prefix, body = (raw[:1], raw[1:]) if raw[:1] in {"+", "-", " "} else ("", raw)
        if in_key or has_secret(body):
            out.append(prefix + REDACTED)
            if PRIVATE_KEY_BEGIN.search(body):
                in_key = True
            if PRIVATE_KEY_END.search(body):
                in_key = False
            continue
        out.append(raw)
    return "\n".join(out)


def to_findings(secrets: list[SecretFinding]) -> list[Finding]:
    """Collapse secret hits into one high-severity Finding for the comment."""
    if not secrets:
        return []
    details = [
        f"{s.filename}" + (f" line {s.line}" if s.line is not None else "")
        + f": {s.kind} ({s.masked})"
        for s in secrets[:MAX_REPORTED]
    ]
    if len(secrets) > MAX_REPORTED:
        details.append(f"…and {len(secrets) - MAX_REPORTED} more")
    message = (
        f"Possible secrets in added lines ({len(secrets)}). Rotate any real credential; "
        "removing it in a later commit does not remove it from git history."
    )
    files = tuple(dict.fromkeys(s.filename for s in secrets))
    return [Finding("secrets", "high", message, files, tuple(details))]

"""Renders the review results into the Markdown PR comment, tagged with
BOT_COMMENT_MARKER so the bot can find and update its own comment.

Untrusted text (filenames, finding details) is always placed in inline code spans so it
cannot inject HTML, Markdown links or @mentions. The output always stays below GitHub's
65,536-character comment limit.
"""

from collections.abc import Sequence

from app.analysis.rules import SEVERITY_ORDER, Finding, PRFile, Severity

GITHUB_COMMENT_LIMIT = 65_536
MAX_COMMENT_CHARS = 65_000  # safety margin below GitHub's limit
MAX_FILES_PER_FINDING = 20
FOOTER = "\n---\n<sub>Automated review — rules v1</sub>\n"
TRUNCATED_NOTICE = "\n\n_…comment truncated to fit GitHub's size limit._\n"
SUMMARY_UNAVAILABLE = "_Summary unavailable._"

RISK_LABEL: dict[Severity | None, str] = {
    "high": "🔴 High",
    "warn": "🟡 Medium",
    "info": "🟢 Low",
    None: "🟢 Low",
}
SEVERITY_HEADING: dict[Severity, str] = {
    "high": "🔴 High",
    "warn": "🟡 Warning",
    "info": "🔵 Info",
}


def inline_code(text: str, *, in_table: bool = False) -> str:
    """Wrap untrusted text in a code span that cannot be broken out of (or break a table)."""
    cleaned = text.replace("`", "'").replace("\n", " ").replace("\r", " ")
    if in_table:
        cleaned = cleaned.replace("|", "\\|")
    return f"`{cleaned}`"


def risk_level(findings: Sequence[Finding]) -> Severity | None:
    if not findings:
        return None
    return min((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__)


def _render_finding(finding: Finding) -> list[str]:
    lines = [f"- **{finding.rule_id}** — {finding.message}"]
    items = finding.details or finding.files
    for item in items[:MAX_FILES_PER_FINDING]:
        lines.append(f"  - {inline_code(item)}")
    if len(items) > MAX_FILES_PER_FINDING:
        lines.append(f"  - …and {len(items) - MAX_FILES_PER_FINDING} more")
    return lines


def _render_head(marker: str, findings: Sequence[Finding], summary: str | None) -> str:
    lines = [
        marker,
        f"## PR Review — Risk: {RISK_LABEL[risk_level(findings)]}",
        "",
        "### Summary",
        summary.strip() if summary and summary.strip() else SUMMARY_UNAVAILABLE,
        "",
        "### Findings",
    ]
    if not findings:
        lines.append("No findings. ✅")
    for severity in ("high", "warn", "info"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        lines += ["", f"#### {SEVERITY_HEADING[severity]} ({len(group)})"]
        for finding in group:
            lines += _render_finding(finding)
    return "\n".join(lines) + "\n"


def _render_details(
    files: Sequence[PRFile], findings: Sequence[Finding], max_rows: int
) -> str:
    if not files:
        return ""
    flags: dict[str, list[str]] = {}
    for finding in findings:
        for name in finding.files:
            if finding.rule_id not in flags.setdefault(name, []):
                flags[name].append(finding.rule_id)

    lines = [
        "",
        f"<details><summary>Changed files ({len(files)})</summary>",
        "",
        "| File | Status | + | − | Flags |",
        "|---|---|---:|---:|---|",
    ]
    for f in files[:max_rows]:
        rule_ids = ", ".join(flags.get(f.filename, [])) or "—"
        name = inline_code(f.filename, in_table=True)
        lines.append(f"| {name} | {f.status} | {f.additions} | {f.deletions} | {rule_ids} |")
    if len(files) > max_rows:
        lines.append(f"| …and {len(files) - max_rows} more files | | | | |")
    lines += ["", "</details>", ""]
    return "\n".join(lines)


def render_comment(
    *,
    marker: str,
    files: Sequence[PRFile],
    findings: Sequence[Finding],
    summary: str | None = None,
    max_chars: int = MAX_COMMENT_CHARS,
) -> str:
    """Render the full PR comment. `summary=None` renders "Summary unavailable"."""
    head = _render_head(marker, findings, summary)
    for max_rows in dict.fromkeys((len(files), 300, 100, 25)):
        text = head + _render_details(files, findings, max_rows) + FOOTER
        if len(text) <= max_chars:
            return text
    text = head + FOOTER
    if len(text) <= max_chars:
        return text
    budget = max_chars - len(FOOTER) - len(TRUNCATED_NOTICE)
    return head[:budget] + TRUNCATED_NOTICE + FOOTER

from app.analysis.rules import Finding, PRFile
from app.comment import (
    GITHUB_COMMENT_LIMIT,
    SUMMARY_UNAVAILABLE,
    inline_code,
    render_comment,
    risk_level,
)

MARKER = "<!-- pr-review-bot -->"
FOOTER_TEXT = "Automated review — rules v1"

HIGH = Finding(
    "secrets", "high", "Possible secrets.", ("a.py",), ("a.py line 3: GitHub token (ghp_****)",)
)
WARN = Finding("missing_tests", "warn", "No tests.", ("app/main.py",))
INFO = Finding("deleted_files", "info", "1 file(s) deleted.", ("old.py",))
FILES = [
    PRFile("a.py", "added", 10, 0, "@@"),
    PRFile("app/main.py", "modified", 3, 1, "@@"),
    PRFile("old.py", "removed", 0, 5, "@@"),
]


def test_risk_level() -> None:
    assert risk_level([]) is None
    assert risk_level([INFO]) == "info"
    assert risk_level([INFO, WARN]) == "warn"
    assert risk_level([WARN, HIGH, INFO]) == "high"


def test_comment_structure() -> None:
    body = render_comment(
        marker=MARKER, files=FILES, findings=[INFO, HIGH, WARN], summary="- Adds a thing"
    )

    assert body.startswith(MARKER)
    assert "Risk: 🔴 High" in body
    assert "### Summary\n- Adds a thing" in body
    # grouped by severity, high first
    assert body.index("#### 🔴 High") < body.index("#### 🟡 Warning") < body.index("#### 🔵 Info")
    assert "`a.py line 3: GitHub token (ghp_****)`" in body
    assert "<details><summary>Changed files (3)</summary>" in body
    assert "| `app/main.py` | modified | 3 | 1 | missing_tests |" in body
    assert body.rstrip().endswith(f"<sub>{FOOTER_TEXT}</sub>")


def test_no_summary_says_unavailable_and_still_shows_findings() -> None:
    body = render_comment(marker=MARKER, files=FILES, findings=[WARN], summary=None)

    assert SUMMARY_UNAVAILABLE in body
    assert "**missing_tests**" in body
    assert "Risk: 🟡 Medium" in body


def test_no_findings() -> None:
    body = render_comment(marker=MARKER, files=FILES, findings=[], summary="ok")
    assert "No findings." in body
    assert "Risk: 🟢 Low" in body


def test_untrusted_filenames_are_neutralised() -> None:
    evil = "x`<img src=x>@admin|y.py"
    body = render_comment(
        marker=MARKER,
        files=[PRFile(evil, "added", 1, 0, "@@")],
        findings=[Finding("missing_tests", "warn", "No tests.", (evil,))],
    )

    assert "`x'<img src=x>@admin|y.py`" in body  # finding list: inside a code span
    assert "| `x'<img src=x>@admin\\|y.py` |" in body  # table: pipe escaped too
    assert "x`<img" not in body


def test_inline_code_strips_newlines() -> None:
    assert inline_code("a\nb") == "`a b`"


def test_many_files_in_one_finding_are_capped() -> None:
    names = tuple(f"f{i}.py" for i in range(30))
    body = render_comment(
        marker=MARKER, files=[], findings=[Finding("missing_tests", "warn", "m", names)]
    )
    assert "`f19.py`" in body
    assert "`f20.py`" not in body
    assert "…and 10 more" in body


def test_huge_file_list_is_truncated_under_limit() -> None:
    files = [PRFile(f"src/{'d' * 200}/file_{i}.py", "modified", 1, 1, "@@") for i in range(3000)]

    body = render_comment(marker=MARKER, files=files, findings=[WARN], summary="s")

    assert len(body) < GITHUB_COMMENT_LIMIT
    assert body.startswith(MARKER)
    assert "**missing_tests**" in body
    assert "more files" in body
    assert body.count("<details>") == body.count("</details>")
    assert FOOTER_TEXT in body


def test_huge_summary_is_hard_truncated_under_limit() -> None:
    body = render_comment(marker=MARKER, files=FILES, findings=[HIGH], summary="x" * 200_000)

    assert len(body) < GITHUB_COMMENT_LIMIT
    assert body.startswith(MARKER)
    assert "truncated" in body
    assert body.rstrip().endswith(f"<sub>{FOOTER_TEXT}</sub>")


def test_custom_max_chars() -> None:
    body = render_comment(marker=MARKER, files=FILES, findings=[HIGH], max_chars=300)
    assert len(body) <= 300
    assert body.startswith(MARKER)

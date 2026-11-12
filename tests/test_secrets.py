import pytest

from app.analysis.rules import PRFile
from app.analysis.secrets import (
    REDACTED,
    SecretFinding,
    iter_added_lines,
    mask,
    redact_patch,
    scan_files,
    scan_patch,
    to_findings,
)

# Fake secrets are assembled at runtime so no secret-shaped literal sits in the repo
# (keeps GitHub push protection and secret scanners quiet).
AWS_KEY = "AKIA" + "Q" * 16
GH_TOKEN = "gh" + "p_" + "a1B2" * 9
GH_PAT = "github" + "_pat_" + "x" * 30
SLACK_TOKEN = "xo" + "xb-" + "1234567890-abcdef"
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END " + "RSA PRIVATE KEY-----"
PASSWORD = "hunter2-very-long"


# --- hunk / line-number parsing ---------------------------------------------


def test_iter_added_lines_tracks_new_file_line_numbers() -> None:
    patch = "\n".join(
        [
            "@@ -1,3 +1,4 @@",
            " line1",  # new 1
            "-old",  # not counted
            "+added2",  # new 2
            " line3",  # new 3
            "+added4",  # new 4
            "@@ -20,2 +40,3 @@ def f():",
            " ctx",  # new 40
            "+added41",  # new 41
            "\\ No newline at end of file",
        ]
    )

    assert list(iter_added_lines(patch)) == [(2, "added2"), (4, "added4"), (41, "added41")]


def test_iter_added_lines_new_file_hunk() -> None:
    assert list(iter_added_lines("@@ -0,0 +1,2 @@\n+a\n+b")) == [(1, "a"), (2, "b")]


def test_iter_added_lines_single_line_hunk_without_count() -> None:
    assert list(iter_added_lines("@@ -5 +7 @@\n-x\n+y")) == [(7, "y")]


# --- detection --------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (f"aws_key = {AWS_KEY}", "AWS access key"),
        (f"TOKEN={GH_TOKEN}", "GitHub token"),
        (f"pat: {GH_PAT}", "GitHub token"),
        (f"slack {SLACK_TOKEN}", "Slack token"),
        (PEM_HEADER, "Private key"),
        ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "Private key"),
        (f'password = "{PASSWORD}"', "Hardcoded credential"),
        (f"API_KEY: '{PASSWORD}'", "Hardcoded credential"),
        (f'"client_secret": "{PASSWORD}"', "Hardcoded credential"),
        (f'self.auth_token = "{PASSWORD}"', "Hardcoded credential"),
    ],
)
def test_detects_secret_kinds(line: str, kind: str) -> None:
    findings = scan_patch("f.py", f"@@ -0,0 +1 @@\n+{line}")
    assert kind in {f.kind for f in findings}


@pytest.mark.parametrize(
    "line",
    [
        'password = ""',
        "password = os.environ['DB_PASSWORD']",
        'token = "short"',
        "api_key = settings.api_key",
        "AKIA_TOO_SHORT",
    ],
)
def test_ignores_non_secrets(line: str) -> None:
    assert scan_patch("f.py", f"@@ -0,0 +1 @@\n+{line}") == []


def test_only_added_lines_are_scanned() -> None:
    patch = f"@@ -1,2 +1,1 @@\n-old = {AWS_KEY}\n {GH_TOKEN}"
    assert scan_patch("f.py", patch) == []


def test_reports_file_and_new_line_number() -> None:
    patch = f"@@ -10,2 +12,3 @@\n ctx\n+ok = 1\n+key = {AWS_KEY}"

    assert scan_patch("cfg/settings.py", patch) == [
        SecretFinding("cfg/settings.py", 14, "AWS access key", "AKIA****")
    ]


def test_scan_files_skips_patchless() -> None:
    files = [
        PRFile("bin.dat", "added", 0, 0, None),
        PRFile("a.py", "added", 1, 0, f"@@ -0,0 +1 @@\n+{GH_TOKEN}"),
    ]
    assert [f.filename for f in scan_files(files)] == ["a.py"]


# --- masking ----------------------------------------------------------------


def test_mask_keeps_four_chars() -> None:
    assert mask(GH_TOKEN) == "ghp_****"


def test_findings_never_contain_full_secret() -> None:
    patch = "@@ -0,0 +1,3 @@\n" + "\n".join(
        [f"+{AWS_KEY}", f"+{GH_TOKEN}", f'+password = "{PASSWORD}"']
    )
    findings = scan_patch("a.py", patch)
    rendered = repr(findings) + repr(to_findings(findings))

    for secret in (AWS_KEY, GH_TOKEN, PASSWORD):
        assert secret not in rendered
    assert "hunt****" in rendered


def test_to_findings_is_one_high_finding_with_line_details() -> None:
    [finding] = to_findings(
        [
            SecretFinding("a.py", 3, "GitHub token", "ghp_****"),
            SecretFinding("b.py", None, "AWS access key", "AKIA****"),
        ]
    )
    assert finding.rule_id == "secrets"
    assert finding.severity == "high"
    assert finding.files == ("a.py", "b.py")
    assert finding.details == (
        "a.py line 3: GitHub token (ghp_****)",
        "b.py: AWS access key (AKIA****)",
    )


def test_to_findings_empty() -> None:
    assert to_findings([]) == []


# --- redaction --------------------------------------------------------------


def test_redact_patch_replaces_flagged_lines() -> None:
    patch = f"@@ -1,2 +1,3 @@\n ctx\n+safe = 1\n+key = {AWS_KEY}"

    redacted = redact_patch(patch)

    assert redacted.splitlines() == ["@@ -1,2 +1,3 @@", " ctx", "+safe = 1", f"+{REDACTED}"]
    assert AWS_KEY not in redacted


def test_redact_patch_also_redacts_removed_and_context_lines() -> None:
    patch = f"@@ -1,2 +1,1 @@\n-old = {GH_TOKEN}\n tok = {GH_TOKEN}"
    assert GH_TOKEN not in redact_patch(patch)


def test_redact_patch_redacts_whole_private_key_block() -> None:
    body = "MIIEowIBAAKCAQEAexamplekeymaterial"
    patch = "\n".join(
        ["@@ -0,0 +1,4 @@", f"+{PEM_HEADER}", f"+{body}", f"+{PEM_FOOTER}", "+after = 1"]
    )

    redacted = redact_patch(patch)

    assert body not in redacted
    assert redacted.splitlines()[-1] == "+after = 1"
    assert redacted.count(REDACTED) == 3

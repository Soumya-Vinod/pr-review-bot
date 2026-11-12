import pytest

from app.analysis.rules import (
    Finding,
    PRFile,
    RuleConfig,
    deleted_files,
    is_test_file,
    large_pr,
    missing_tests,
    run_rules,
    sensitive_files,
    unreviewable,
)


def pr_file(
    name: str,
    *,
    status: str = "modified",
    additions: int = 1,
    deletions: int = 0,
    patch: str | None = "@@ -1 +1 @@\n+x",
) -> PRFile:
    return PRFile(name, status, additions, deletions, patch)


def test_from_api_handles_missing_patch() -> None:
    f = PRFile.from_api({"filename": "logo.png", "status": "added", "additions": 0, "deletions": 0})
    assert f == PRFile("logo.png", "added", 0, 0, None)


# --- large_pr ---------------------------------------------------------------


def test_large_pr_below_thresholds() -> None:
    assert large_pr([pr_file("a.py", additions=200, deletions=199)]) == []


def test_large_pr_by_lines() -> None:
    [finding] = large_pr([pr_file("a.py", additions=300, deletions=100)])
    assert finding.rule_id == "large_pr"
    assert finding.severity == "warn"
    assert "400 changed lines" in finding.message


def test_large_pr_by_file_count() -> None:
    assert large_pr([pr_file(f"f{i}.py") for i in range(20)])


def test_large_pr_thresholds_are_configurable() -> None:
    config = RuleConfig(large_pr_lines=10, large_pr_files=100)
    assert large_pr([pr_file("a.py", additions=10)], config)
    assert not large_pr([pr_file("a.py", additions=9)], config)


# --- sensitive_files --------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.production",
        "config/.env.local",
        ".github/workflows/ci.yml",
        ".github/workflows/deploy/release.yaml",
    ],
)
def test_sensitive_high(path: str) -> None:
    [finding] = sensitive_files([pr_file(path)])
    assert finding.severity == "high"
    assert finding.files == (path,)


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "Dockerfile",
        "docker/Dockerfile.prod",
        "docker-compose.yml",
        "docker-compose.override.yaml",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "web/package.json",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "go.sum",
        "app/migrations/0001_initial.py",
        "db/migrations/2024/01_add.sql",
    ],
)
def test_sensitive_warn(path: str) -> None:
    [finding] = sensitive_files([pr_file(path)])
    assert finding.severity == "warn"


@pytest.mark.parametrize(
    "path", ["app/main.py", "docs/environment.md", "src/migrations.py", "workflows/ci.yml"]
)
def test_not_sensitive(path: str) -> None:
    assert sensitive_files([pr_file(path)]) == []


def test_sensitive_groups_by_severity() -> None:
    findings = sensitive_files([pr_file(".env"), pr_file("Dockerfile"), pr_file("yarn.lock")])
    assert [(f.severity, f.files) for f in findings] == [
        ("high", (".env",)),
        ("warn", ("Dockerfile", "yarn.lock")),
    ]


# --- missing_tests ----------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_app.py",
        "app/test_utils.py",
        "pkg/utils_test.go",
        "web/src/button.test.tsx",
        "web/src/button.spec.js",
        "src/test/java/FooTest.java",
        "web/__tests__/a.js",
        "conftest.py",
    ],
)
def test_is_test_file(path: str) -> None:
    assert is_test_file(path)


@pytest.mark.parametrize("path", ["app/latest.py", "contest.py", "app/main.py"])
def test_is_not_test_file(path: str) -> None:
    assert not is_test_file(path)


def test_missing_tests_flags_source_without_tests() -> None:
    [finding] = missing_tests([pr_file("app/main.py"), pr_file("README.md")])
    assert finding.rule_id == "missing_tests"
    assert finding.files == ("app/main.py",)


def test_missing_tests_ok_when_tests_touched() -> None:
    assert missing_tests([pr_file("app/main.py"), pr_file("tests/test_main.py")]) == []


def test_missing_tests_ignores_docs_and_deleted_source() -> None:
    assert missing_tests([pr_file("README.md"), pr_file("old.py", status="removed")]) == []


# --- unreviewable / deleted -------------------------------------------------


def test_unreviewable_lists_patchless_files() -> None:
    [finding] = unreviewable([pr_file("logo.png", patch=None), pr_file("a.py")])
    assert finding.severity == "info"
    assert finding.files == ("logo.png",)


def test_unreviewable_skips_removed_files() -> None:
    assert unreviewable([pr_file("old.bin", status="removed", patch=None)]) == []


def test_deleted_files() -> None:
    [finding] = deleted_files([pr_file("old.py", status="removed"), pr_file("a.py")])
    assert finding.rule_id == "deleted_files"
    assert finding.files == ("old.py",)


def test_deleted_files_none() -> None:
    assert deleted_files([pr_file("a.py")]) == []


# --- run_rules --------------------------------------------------------------


def test_run_rules_sorts_high_first() -> None:
    findings = run_rules(
        [pr_file("app/main.py"), pr_file(".env"), pr_file("gone.py", status="removed")]
    )
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), key=["high", "warn", "info"].index
    )
    assert findings[0] == Finding(
        "sensitive_files",
        "high",
        "Changes to secrets-bearing or CI files; review carefully.",
        (".env",),
    )
    assert {f.rule_id for f in findings} == {"sensitive_files", "missing_tests", "deleted_files"}


def test_run_rules_clean_pr() -> None:
    assert run_rules([pr_file("app/main.py"), pr_file("tests/test_main.py")]) == []

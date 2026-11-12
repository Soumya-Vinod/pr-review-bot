"""Deterministic, rule-based checks on a PR's changed files.

Every rule is a pure function: list[PRFile] -> list[Finding]. Rules never need the LLM.
"""

import posixpath
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import partial
from typing import Any, Literal

Severity = Literal["info", "warn", "high"]
SEVERITY_ORDER: dict[Severity, int] = {"high": 0, "warn": 1, "info": 2}


@dataclass(frozen=True, slots=True)
class PRFile:
    filename: str
    status: str  # added | modified | removed | renamed | copied | changed | unchanged
    additions: int
    deletions: int
    patch: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "PRFile":
        """Build from one entry of GET /repos/{repo}/pulls/{n}/files."""
        patch = data.get("patch")
        return cls(
            filename=str(data["filename"]),
            status=str(data.get("status", "modified")),
            additions=int(data.get("additions", 0)),
            deletions=int(data.get("deletions", 0)),
            patch=patch if isinstance(patch, str) else None,
        )


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    files: tuple[str, ...] = ()
    # Optional per-item lines shown instead of the plain file list (e.g. "file line 3: ...").
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleConfig:
    large_pr_lines: int = 400
    large_pr_files: int = 20


# --- path classification ---------------------------------------------------------

LOCKFILES = frozenset(
    {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock", "cargo.lock",
        "gemfile.lock", "composer.lock", "go.sum", "packages.lock.json", "bun.lockb",
    }
)
ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})
SOURCE_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java", ".kt",
        ".rs", ".cs", ".php", ".swift", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp",
    }
)
TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "testing"})


def _basename(path: str) -> str:
    return posixpath.basename(path).lower()


def _dirs(path: str) -> list[str]:
    return [part.lower() for part in path.split("/")[:-1]]


def is_lockfile(path: str) -> bool:
    return _basename(path) in LOCKFILES


def is_test_file(path: str) -> bool:
    name = _basename(path)
    stem = posixpath.splitext(name)[0]
    original_stem = posixpath.splitext(posixpath.basename(path))[0]
    return (
        any(part in TEST_DIRS for part in _dirs(path))
        or stem.startswith("test_")
        or stem.endswith(("_test", "_spec", ".test", ".spec"))
        or original_stem.endswith(("Test", "Tests"))  # FooTest.java, BarTests.cs
        or name == "conftest.py"
    )


def is_source_file(path: str) -> bool:
    return posixpath.splitext(_basename(path))[1] in SOURCE_EXTENSIONS and not is_test_file(path)


def sensitive_reason(path: str) -> tuple[Severity, str] | None:
    """Return (severity, why) if a path is sensitive, else None."""
    name = _basename(path)
    lowered = path.lower()
    if name.startswith(".env"):
        if name in ENV_TEMPLATES:
            return "warn", "environment template"
        return "high", "environment file (may contain secrets)"
    if lowered.startswith(".github/workflows/"):
        return "high", "CI workflow"
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "warn", "container build"
    if name.startswith("docker-compose") or name.startswith("compose."):
        return "warn", "container orchestration"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "warn", "dependencies"
    if name in {"pyproject.toml", "package.json"}:
        return "warn", "dependencies / build config"
    if name in LOCKFILES:
        return "warn", "lockfile"
    if "migrations" in _dirs(path):
        return "warn", "database migration"
    return None


# --- rules -----------------------------------------------------------------------


def large_pr(files: list[PRFile], config: RuleConfig | None = None) -> list[Finding]:
    config = config or RuleConfig()
    changed = sum(f.additions + f.deletions for f in files)
    if changed < config.large_pr_lines and len(files) < config.large_pr_files:
        return []
    return [
        Finding(
            "large_pr",
            "warn",
            f"Large PR: {changed} changed lines across {len(files)} files "
            f"(thresholds: {config.large_pr_lines} lines or {config.large_pr_files} files). "
            "Consider splitting it.",
        )
    ]


def sensitive_files(files: list[PRFile]) -> list[Finding]:
    grouped: dict[Severity, list[str]] = {}
    for f in files:
        reason = sensitive_reason(f.filename)
        if reason:
            grouped.setdefault(reason[0], []).append(f.filename)
    findings = []
    if "high" in grouped:
        findings.append(
            Finding(
                "sensitive_files",
                "high",
                "Changes to secrets-bearing or CI files; review carefully.",
                tuple(grouped["high"]),
            )
        )
    if "warn" in grouped:
        findings.append(
            Finding(
                "sensitive_files",
                "warn",
                "Changes to build, dependency or migration files.",
                tuple(grouped["warn"]),
            )
        )
    return findings


def missing_tests(files: list[PRFile]) -> list[Finding]:
    source = [f.filename for f in files if f.status != "removed" and is_source_file(f.filename)]
    if not source or any(is_test_file(f.filename) for f in files):
        return []
    return [
        Finding(
            "missing_tests",
            "warn",
            "Source code changed but no test files were touched.",
            tuple(source),
        )
    ]


def unreviewable(files: list[PRFile]) -> list[Finding]:
    names = [f.filename for f in files if f.patch is None and f.status != "removed"]
    if not names:
        return []
    return [
        Finding(
            "unreviewable",
            "info",
            "No diff available (binary or too large); these files were not analysed.",
            tuple(names),
        )
    ]


def deleted_files(files: list[PRFile]) -> list[Finding]:
    names = [f.filename for f in files if f.status == "removed"]
    if not names:
        return []
    return [Finding("deleted_files", "info", f"{len(names)} file(s) deleted.", tuple(names))]


def run_rules(files: list[PRFile], config: RuleConfig | None = None) -> list[Finding]:
    """Run every rule and return findings sorted by severity (high first)."""
    rules: Iterable[Callable[[list[PRFile]], list[Finding]]] = (
        partial(large_pr, config=config or RuleConfig()),
        sensitive_files,
        missing_tests,
        unreviewable,
        deleted_files,
    )
    findings = [finding for rule in rules for finding in rule(files)]
    return sort_findings(findings)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])

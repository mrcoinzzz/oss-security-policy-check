from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecurityCheck:
    name: str
    passed: bool
    detail: str
    weight: int = 10


@dataclass(frozen=True)
class SecurityReport:
    root: Path
    checks: tuple[SecurityCheck, ...]

    @property
    def passed_points(self) -> int:
        return sum(check.weight for check in self.checks if check.passed)

    @property
    def total_points(self) -> int:
        return sum(check.weight for check in self.checks)

    @property
    def score(self) -> int:
        if self.total_points == 0:
            return 0
        return round((self.passed_points / self.total_points) * 100)


def check_security_policy(root: str | Path) -> SecurityReport:
    repo_root = Path(root).expanduser().resolve()
    if not repo_root.exists():
        raise FileNotFoundError(f"Path does not exist: {repo_root}")
    if not repo_root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {repo_root}")

    policy_path = _security_policy_path(repo_root)
    policy_text = policy_path.read_text(encoding="utf-8", errors="ignore").lower() if policy_path else ""

    checks = (
        _file_check(repo_root, "README", ("README.md", "README.rst", "README.txt")),
        _file_check(repo_root, "License", ("LICENSE", "LICENSE.md", "COPYING")),
        SecurityCheck("Security policy", policy_path is not None, f"{policy_path.name} found" if policy_path else "Add SECURITY.md"),
        _text_check("Reporting instructions", policy_text, ("report", "contact", "email", "issue")),
        _text_check("Supported versions", policy_text, ("supported version", "supported versions", "currently supported")),
        _text_check("Disclosure guidance", policy_text, ("disclosure", "public", "responsible", "coordinate")),
        _text_check("Impact language", policy_text, ("impact", "severity", "vulnerability")),
        _text_check("Dependency mention", policy_text, ("dependency", "dependencies", "supply chain", "package")),
        _file_check(repo_root, "CI workflow", (".github/workflows",)),
        _file_check(repo_root, "Dependabot config", (".github/dependabot.yml", ".github/dependabot.yaml")),
    )
    return SecurityReport(root=repo_root, checks=checks)


def _security_policy_path(root: Path) -> Path | None:
    for candidate in (root / "SECURITY.md", root / ".github" / "SECURITY.md"):
        if candidate.exists():
            return candidate
    return None


def _file_check(root: Path, name: str, candidates: tuple[str, ...]) -> SecurityCheck:
    for candidate in candidates:
        if (root / candidate).exists():
            return SecurityCheck(name, True, f"{candidate} found")
    return SecurityCheck(name, False, f"Missing one of: {', '.join(candidates)}")


def _text_check(name: str, text: str, terms: tuple[str, ...]) -> SecurityCheck:
    if any(term in text for term in terms):
        return SecurityCheck(name, True, "Relevant wording found")
    return SecurityCheck(name, False, f"Add wording for: {', '.join(terms)}")

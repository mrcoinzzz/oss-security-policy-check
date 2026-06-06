from pathlib import Path

from oss_security_policy_check.checker import check_security_policy


def test_security_policy_text_checks_pass(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Project\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(
        "Report vulnerabilities by email. Supported versions are listed. "
        "Please coordinate responsible disclosure. Include impact and dependency details.",
        encoding="utf-8",
    )

    report = check_security_policy(tmp_path)
    passed = {check.name for check in report.checks if check.passed}

    assert "Security policy" in passed
    assert "Reporting instructions" in passed
    assert "Supported versions" in passed
    assert "Disclosure guidance" in passed


def test_missing_security_policy_warns(tmp_path: Path) -> None:
    report = check_security_policy(tmp_path)
    security_policy = next(check for check in report.checks if check.name == "Security policy")

    assert security_policy.passed is False

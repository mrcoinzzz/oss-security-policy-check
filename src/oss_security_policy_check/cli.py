from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import SecurityReport, check_security_policy


SECURITY_TEMPLATE = """# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before sharing public details.

Include:

- A short description of the issue
- Steps to reproduce
- Potential impact or severity
- Affected versions, packages, or dependencies
- Suggested mitigation, if known

## Supported Versions

The latest release and the current main branch are supported unless documented otherwise.

## Responsible Disclosure

Please give maintainers a reasonable opportunity to investigate and coordinate a fix before public disclosure.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oss-security-policy-check",
        description="Check a repository for open-source security policy readiness.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to check")
    parser.add_argument("--min-score", type=int, default=70, help="Minimum passing score")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--print-template", action="store_true", help="Print a starter SECURITY.md template and exit")
    parser.add_argument("--write-template", help="Write a starter SECURITY.md template to a file and exit")
    parser.add_argument("--force", action="store_true", help="Allow --write-template to overwrite an existing file")
    args = parser.parse_args(argv)

    if args.print_template:
        print(SECURITY_TEMPLATE, end="")
        return 0
    if args.write_template:
        return _write_template(Path(args.write_template), args.force)

    try:
        report = check_security_policy(Path(args.path))
    except (FileNotFoundError, NotADirectoryError) as error:
        print(str(error), file=sys.stderr)
        return 2

    if args.format == "json":
        print(_json(report))
    elif args.format == "markdown":
        print(_markdown(report, args.min_score))
    else:
        print(_text(report, args.min_score))
    return 0 if report.score >= args.min_score else 1


def _text(report: SecurityReport, min_score: int) -> str:
    lines = [
        f"OSS Security Policy Check: {report.root}",
        "",
        f"Score: {report.score}% ({report.passed_points}/{report.total_points})",
        f"Required: {min_score}%",
        "",
    ]
    for check in report.checks:
        status = "PASS" if check.passed else "WARN"
        lines.append(f"{status:<5} {check.name:<22} {check.detail}")
    return "\n".join(lines)


def _json(report: SecurityReport) -> str:
    return json.dumps(
        {
            "root": str(report.root),
            "score": report.score,
            "points": {"passed": report.passed_points, "total": report.total_points},
            "checks": [
                {
                    "name": check.name,
                    "passed": check.passed,
                    "detail": check.detail,
                    "weight": check.weight,
                }
                for check in report.checks
            ],
        },
        indent=2,
    )


def _markdown(report: SecurityReport, min_score: int) -> str:
    lines = [
        "# OSS Security Policy Check",
        "",
        f"Repository: `{report.root}`",
        "",
        f"Score: **{report.score}% ({report.passed_points}/{report.total_points})**",
        f"Required: **{min_score}%**",
        "",
        "| Status | Check | Detail |",
        "| --- | --- | --- |",
    ]

    for check in report.checks:
        status = "PASS" if check.passed else "WARN"
        lines.append(f"| {status} | {check.name} | {check.detail} |")

    return "\n".join(lines)


def _write_template(path: Path, force: bool) -> int:
    if path.exists() and not force:
        print(f"Template target already exists: {path}", file=sys.stderr)
        return 2

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(SECURITY_TEMPLATE, encoding="utf-8")
    except OSError as error:
        print(f"Could not write security template: {error}", file=sys.stderr)
        return 2

    print(f"Wrote security template: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

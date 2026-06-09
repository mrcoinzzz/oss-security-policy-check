from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import SecurityReport, check_security_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oss-security-policy-check",
        description="Check a repository for open-source security policy readiness.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to check")
    parser.add_argument("--min-score", type=int, default=70, help="Minimum passing score")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    args = parser.parse_args(argv)

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


if __name__ == "__main__":
    raise SystemExit(main())

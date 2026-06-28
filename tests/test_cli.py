from pathlib import Path

from oss_security_policy_check.cli import main


def test_cli_outputs_score(tmp_path: Path, capsys) -> None:
    (tmp_path / "SECURITY.md").write_text("Report vulnerabilities by email.", encoding="utf-8")

    exit_code = main([str(tmp_path), "--min-score", "0"])

    assert exit_code == 0
    assert "Score:" in capsys.readouterr().out


def test_cli_can_output_markdown(tmp_path: Path, capsys) -> None:
    (tmp_path / "SECURITY.md").write_text("Report vulnerabilities by email.", encoding="utf-8")

    exit_code = main([str(tmp_path), "--min-score", "0", "--format", "markdown"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "# OSS Security Policy Check" in output
    assert "| Status | Check | Detail |" in output
    assert "| PASS | Security policy | SECURITY.md found |" in output


def test_cli_can_print_security_template(capsys) -> None:
    exit_code = main(["--print-template"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "# Security Policy" in output
    assert "Reporting a Vulnerability" in output
    assert "Supported Versions" in output


def test_cli_can_write_security_template(tmp_path: Path, capsys) -> None:
    target = tmp_path / "SECURITY.md"

    exit_code = main(["--write-template", str(target)])

    assert exit_code == 0
    assert "Wrote security template" in capsys.readouterr().out
    assert "Reporting a Vulnerability" in target.read_text(encoding="utf-8")


def test_cli_refuses_to_overwrite_template_without_force(tmp_path: Path, capsys) -> None:
    target = tmp_path / "SECURITY.md"
    target.write_text("existing\n", encoding="utf-8")

    exit_code = main(["--write-template", str(target)])

    assert exit_code == 2
    assert "already exists" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "existing\n"


def test_cli_can_write_security_report_to_file(tmp_path: Path, capsys) -> None:
    (tmp_path / "SECURITY.md").write_text("Report vulnerabilities by email.", encoding="utf-8")
    output_path = tmp_path / "reports" / "security.md"

    exit_code = main([str(tmp_path), "--min-score", "0", "--format", "markdown", "--output", str(output_path)])

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    output = output_path.read_text(encoding="utf-8")
    assert "# OSS Security Policy Check" in output
    assert "| PASS | Security policy | SECURITY.md found |" in output

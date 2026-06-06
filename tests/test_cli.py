from pathlib import Path

from oss_security_policy_check.cli import main


def test_cli_outputs_score(tmp_path: Path, capsys) -> None:
    (tmp_path / "SECURITY.md").write_text("Report vulnerabilities by email.", encoding="utf-8")

    exit_code = main([str(tmp_path), "--min-score", "0"])

    assert exit_code == 0
    assert "Score:" in capsys.readouterr().out

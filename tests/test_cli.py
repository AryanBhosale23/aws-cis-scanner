from click.testing import CliRunner

from scanner.cli import main


def test_scanner_run_prints_a_result_for_check_1(ctx, tmp_path):
    result = CliRunner().invoke(main, ["run", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "IAM-01" in result.output
    assert "********9012" in result.output  # account id is masked on screen
    assert "123456789012" not in result.output

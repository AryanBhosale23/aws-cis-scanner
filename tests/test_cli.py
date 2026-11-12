import re

from click.testing import CliRunner

from scanner.cli import main


def test_scanner_run_prints_a_result_for_check_1(ctx, tmp_path):
    result = CliRunner().invoke(main, ["run", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "IAM-01" in result.output
    assert "********9012" in result.output  # account id is masked on screen
    assert "123456789012" not in result.output

def test_scanner_run_summarises_checks_as_well_as_results(ctx, tmp_path):
    result = CliRunner().invoke(main, ["run", "--output", str(tmp_path)])
    assert re.search(r"Summary: \d+ of \d+ checks passed", result.output), result.output
    assert re.search(r"Results: \d+ passed, \d+ failed", result.output), result.output

def test_scanner_run_writes_an_html_report_next_to_the_evidence(ctx, tmp_path):
    result = CliRunner().invoke(main, ["run", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    [report] = tmp_path.glob("*/report.html")
    assert "IAM-01" in report.read_text()
    assert "Report:" in result.output
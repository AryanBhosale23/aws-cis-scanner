from scanner.models import CIS_VERSION, Controls, Evidence, Status, worst_status
from scanner.report import render_report, write_report

CONTROLS = Controls(
    cis=f"{CIS_VERSION}, 2.5",
    nist_800_53_r5="IA-2(1)",
    iso_27001_2022="A.8.5",
    soc2="CC6.1",
)


def make_evidence(check_id="IAM-01", status=Status.PASS, resource="account:123456789012"):
    return Evidence(
        check_id=check_id,
        title="Root account has MFA",
        status=status,
        resource=resource,
        region="us-east-1",
        account_id="123456789012",
        timestamp="2026-11-12T00:26:40Z",
        controls=CONTROLS,
        evidence={"mfa_active": status is Status.PASS},
        remediation="Turn on MFA for the root user.",
    )


def test_worst_status_error_beats_fail_beats_pass():
    ok, bad, err = (make_evidence(status=s) for s in (Status.PASS, Status.FAIL, Status.ERROR))
    assert worst_status([ok]) is Status.PASS
    assert worst_status([ok, bad]) is Status.FAIL
    assert worst_status([ok, bad, err]) is Status.ERROR


def test_report_shows_the_check_its_status_and_its_controls(ctx):
    html = render_report(ctx, [make_evidence(status=Status.FAIL)])
    assert "IAM-01" in html
    assert "Root account has MFA" in html
    assert "FAIL" in html
    assert "IA-2(1)" in html
    assert "Turn on MFA for the root user." in html  # a FAIL shows how to fix it


def test_report_hides_the_full_account_number(ctx):
    html = render_report(ctx, [make_evidence()])
    assert "123456789012" not in html
    assert "********9012" in html


def test_report_escapes_text_so_a_resource_name_cannot_inject_html(ctx):
    evil = make_evidence(status=Status.FAIL, resource="<script>alert(1)</script>")
    html = render_report(ctx, [evil])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_report_counts_checks_and_records(ctx):
    results = [
        make_evidence("IAM-01", Status.PASS),
        make_evidence("IAM-02", Status.FAIL),
        make_evidence("IAM-02", Status.PASS, "user:bob"),
    ]
    html = render_report(ctx, results)
    assert "1 of 2 checks passed" in html
    assert "2 passed, 1 failed, 0 error" in html


def test_report_with_no_results_still_renders(ctx):
    html = render_report(ctx, [])
    assert "No results" in html


def test_write_report_saves_report_html_in_the_run_folder(ctx, tmp_path):
    path = write_report(ctx, [make_evidence()], tmp_path)
    assert path == tmp_path / "report.html"
    assert "IAM-01" in path.read_text()


def test_report_is_plain_ascii_so_no_text_encoding_can_garble_it(ctx):
    resource = "arn:aws:s3:::caf\u00e9-bucket"
    html = render_report(ctx, [make_evidence(status=Status.FAIL, resource=resource)])
    assert html.isascii()


def test_report_shows_only_the_cis_number_not_the_benchmark_name_each_time(ctx):
    html = render_report(ctx, [make_evidence(), make_evidence("IAM-02")])
    assert "CIS CIS" not in html
    assert html.count(CIS_VERSION) == 1  # only in the page header

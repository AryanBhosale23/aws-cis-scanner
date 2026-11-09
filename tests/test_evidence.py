import json

from scanner.checks.iam import root_mfa_enabled
from scanner.evidence import mask_account, write_evidence


def test_mask_account_keeps_last_four():
    assert mask_account("123456789012") == "********9012"


def test_evidence_file_has_the_agreed_fields(ctx, tmp_path):
    run_dir = write_evidence(root_mfa_enabled.run(ctx), tmp_path)
    [record] = json.loads((run_dir / "IAM-01.json").read_text())
    assert set(record) == {
        "check_id", "title", "status", "resource", "region", "account_id",
        "timestamp", "controls", "evidence", "remediation",
    }
    assert set(record["controls"]) == {"cis", "nist_800_53_r5", "iso_27001_2022", "soc2"}
    assert record["status"] in {"PASS", "FAIL", "ERROR"}

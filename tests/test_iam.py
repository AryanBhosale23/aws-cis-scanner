from scanner.checks.iam import root_mfa_enabled
from scanner.models import Status


def test_iam_01_passes_when_root_has_mfa(ctx, iam_backend):
    # moto cannot enable root MFA through its API, so we set its internal flag.
    iam_backend.account_summary._account_mfa_enabled = 1
    [record] = root_mfa_enabled.run(ctx)
    assert record.status is Status.PASS
    assert record.check_id == "IAM-01"
    assert record.evidence == {"AccountMFAEnabled": 1}


def test_iam_01_fails_when_root_has_no_mfa(ctx):
    # moto's default account has no root MFA: this is the failing input.
    [record] = root_mfa_enabled.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"AccountMFAEnabled": 0}


def test_iam_01_carries_its_control_ids(ctx):
    [record] = root_mfa_enabled.run(ctx)
    assert record.controls.nist_800_53_r5 == "IA-2(1)"
    assert record.controls.iso_27001_2022 == "A.8.5"
    assert record.controls.soc2 == "CC6.1"
    assert record.controls.cis.endswith("1.5")


def test_a_failing_aws_call_becomes_error_not_a_crash(ctx, monkeypatch):
    class Boom:
        def client(self, *_a, **_k):
            raise RuntimeError("AccessDenied")

    broken = type(ctx)(session=Boom(), account_id=ctx.account_id, region=ctx.region)
    [record] = root_mfa_enabled.run(broken)
    assert record.status is Status.ERROR
    assert "AccessDenied" in record.evidence["error"]

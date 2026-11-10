from datetime import UTC, datetime, timedelta

import pytest

from scanner.checks import iam
from scanner.checks.iam import console_users_have_mfa, root_has_no_access_keys, root_mfa_enabled
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
    assert record.controls.cis.endswith("2.5")


def test_a_failing_aws_call_becomes_error_not_a_crash(ctx, monkeypatch):
    class Boom:
        def client(self, *_a, **_k):
            raise RuntimeError("AccessDenied")

    broken = type(ctx)(session=Boom(), account_id=ctx.account_id, region=ctx.region)
    [record] = root_mfa_enabled.run(broken)
    assert record.status is Status.ERROR
    assert "AccessDenied" in record.evidence["error"]

def test_iam_02_passes_when_root_has_no_access_keys(ctx):
    [record] = root_has_no_access_keys.run(ctx)
    assert record.status is Status.PASS
    assert record.check_id == "IAM-02"
    assert record.evidence == {"AccountAccessKeysPresent": 0}


def test_iam_02_fails_when_root_has_access_keys(ctx, iam_backend):
    # moto cannot create root keys through its API, so we set its internal flag.
    iam_backend.account_summary._account_access_keys_present = 1
    [record] = root_has_no_access_keys.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"AccountAccessKeysPresent": 1}

def make_user(iam, name, console=False, mfa=False):
    iam.create_user(UserName=name)
    if console:
        iam.create_login_profile(
            UserName=name, Password="Passw0rd!Passw0rd!", PasswordResetRequired=False
        )
    if mfa:
        device = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{name}-mfa")[
            "VirtualMFADevice"
        ]
        iam.enable_mfa_device(
            UserName=name,
            SerialNumber=device["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="234567",
        )
def test_iam_03_fails_for_a_console_user_without_mfa(ctx):
    iam = ctx.session.client("iam")
    make_user(iam, "alice", console=True)
    records = by_user(console_users_have_mfa.run(ctx))
    assert records["alice"].status is Status.FAIL

def by_user(records): return {r.resource.rsplit("/", 1)[-1]: r for r in records}
def test_iam_03_passes_for_a_console_user_with_mfa(ctx):
    iam = ctx.session.client("iam")
    make_user(iam, "carol", console=True, mfa=True)
    records = by_user(console_users_have_mfa.run(ctx))
    assert records["carol"].status is Status.PASS


def test_iam_03_passes_for_a_user_with_no_console_password(ctx):
    iam = ctx.session.client("iam")
    make_user(iam, "bob")
    records = by_user(console_users_have_mfa.run(ctx))
    assert records["bob"].status is Status.PASS

def test_iam_03_every_user_is_its_own_result(ctx):
    iam = ctx.session.client("iam")
    make_user(iam, "alice", console=True)
    make_user(iam, "bob")
    make_user(iam, "carol", console=True, mfa=True)
    records = by_user(console_users_have_mfa.run(ctx))
    assert set(records) == {"alice", "bob", "carol"}
    assert records["alice"].status is Status.FAIL
    assert records["bob"].status is Status.PASS
    assert records["carol"].status is Status.PASS

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def days_ago(n):
    return (NOW - timedelta(days=n)).isoformat()


def make_row(name, **overrides):
    """One fake line of the credential report. Everything is 'off' unless you override it."""
    row = {
        "user": name,
        "arn": f"arn:aws:iam::123456789012:user/{name}",
        "password_enabled": "false",
        "password_last_used": "N/A",
        "password_last_changed": "N/A",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    row.update(overrides)
    return row


@pytest.fixture
def fake_report(monkeypatch):
    def install(*rows):
        monkeypatch.setattr(iam, "_credential_report", lambda ctx: list(rows))
        monkeypatch.setattr(iam, "_utcnow", lambda: NOW)

    return install

def test_iam_04_passes_for_a_recently_used_password(ctx, fake_report):
    fake_report(
        make_row(
            "dave",
            password_enabled="true",
            password_last_changed=days_ago(200),
            password_last_used=days_ago(5),
        )
    )
    records = iam.unused_credentials.run(ctx)
    assert by_user(records)["dave"].status is Status.PASS


def test_iam_04_fails_for_a_password_unused_for_60_days(ctx, fake_report):
    fake_report(
        make_row(
            "erin",
            password_enabled="true",
            password_last_changed=days_ago(200),
            password_last_used=days_ago(60),
        )
    )
    records = iam.unused_credentials.run(ctx)
    assert by_user(records)["erin"].status is Status.FAIL


def test_iam_04_fails_for_an_access_key_that_was_never_used(ctx, fake_report):
    fake_report(
        make_row(
            "frank",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(100),
        )
    )
    records = iam.unused_credentials.run(ctx)
    assert by_user(records)["frank"].status is Status.FAIL
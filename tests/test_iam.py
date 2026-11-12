import json
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

def test_iam_05_passes_for_a_key_rotated_30_days_ago(ctx, fake_report):
    fake_report(
        make_row(
            "gina",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(30),
        )
    )
    records = iam.old_access_keys.run(ctx)
    assert by_user(records)["gina"].status is Status.PASS


def test_iam_05_fails_for_a_key_rotated_120_days_ago(ctx, fake_report):
    fake_report(
        make_row(
            "hank",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(120),
        )
    )
    records = iam.old_access_keys.run(ctx)
    assert by_user(records)["hank"].status is Status.FAIL


def test_iam_05_passes_for_a_key_rotated_exactly_90_days_ago(ctx, fake_report):
    fake_report(
        make_row(
            "iris",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(90),
        )
    )
    records = iam.old_access_keys.run(ctx)
    assert by_user(records)["iris"].status is Status.PASS


def test_iam_05_passes_for_an_old_key_that_is_switched_off(ctx, fake_report):
    fake_report(
        make_row(
            "jack",
            access_key_1_active="false",
            access_key_1_last_rotated=days_ago(300),
        )
    )
    records = iam.old_access_keys.run(ctx)
    assert by_user(records)["jack"].status is Status.PASS

def make_policy(iam, name, *statements):
    """Create a managed policy in the fake AWS and return its ARN."""
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    response = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document))
    return response["Policy"]["Arn"]


def attach_to_new_user(iam, policy_arn, user="alice"):
    """Policies only count when attached, so give this one to a fresh user."""
    iam.create_user(UserName=user)
    iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)


def test_iam_06_fails_for_an_admin_policy_that_is_attached(ctx):
    iam_client = ctx.session.client("iam")
    arn = make_policy(
        iam_client, "god-mode", {"Effect": "Allow", "Action": "*", "Resource": "*"}
    )
    attach_to_new_user(iam_client, arn)

    records = iam.admin_policies.run(ctx)

    assert by_user(records)["god-mode"].status is Status.FAIL


def test_iam_06_passes_for_a_narrow_policy(ctx):
    iam_client = ctx.session.client("iam")
    arn = make_policy(
        iam_client,
        "readonly-s3",
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"},
    )
    attach_to_new_user(iam_client, arn)

    records = iam.admin_policies.run(ctx)

    assert by_user(records)["readonly-s3"].status is Status.PASS


def test_iam_06_passes_for_a_deny_everything_policy(ctx):
    iam_client = ctx.session.client("iam")
    arn = make_policy(
        iam_client, "deny-all", {"Effect": "Deny", "Action": "*", "Resource": "*"}
    )
    attach_to_new_user(iam_client, arn)

    records = iam.admin_policies.run(ctx)

    assert by_user(records)["deny-all"].status is Status.PASS


def test_iam_06_fails_when_admin_is_hidden_inside_lists(ctx):
    iam_client = ctx.session.client("iam")
    arn = make_policy(
        iam_client,
        "sneaky-admin",
        {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]},
    )
    attach_to_new_user(iam_client, arn)

    records = iam.admin_policies.run(ctx)

    assert by_user(records)["sneaky-admin"].status is Status.FAIL


def test_iam_06_ignores_an_admin_policy_that_is_not_attached(ctx):
    iam_client = ctx.session.client("iam")
    make_policy(
        iam_client, "unused-god-mode", {"Effect": "Allow", "Action": "*", "Resource": "*"}
    )

    records = iam.admin_policies.run(ctx)

    assert all(r.status is Status.PASS for r in records)
    assert "unused-god-mode" not in by_user(records)

# ---- IAM-20 password policy ---------------------------------------------------------------


def set_password_policy(ctx, **settings):
    ctx.session.client("iam").update_account_password_policy(**settings)


def test_iam_20_fails_when_no_password_policy_was_set(ctx):
    [record] = iam.password_policy.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["minimum_length"] is None


def test_iam_20_fails_when_passwords_are_too_short(ctx):
    set_password_policy(ctx, MinimumPasswordLength=8, PasswordReusePrevention=24)
    [record] = iam.password_policy.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["problems"] == ["minimum length is below 14"]


def test_iam_20_fails_when_password_reuse_is_not_prevented_enough(ctx):
    set_password_policy(ctx, MinimumPasswordLength=14, PasswordReusePrevention=5)
    [record] = iam.password_policy.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["problems"] == ["password reuse prevention is below 24"]


def test_iam_20_passes_when_length_and_reuse_prevention_are_strong(ctx):
    set_password_policy(ctx, MinimumPasswordLength=14, PasswordReusePrevention=24)
    [record] = iam.password_policy.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence["problems"] == []
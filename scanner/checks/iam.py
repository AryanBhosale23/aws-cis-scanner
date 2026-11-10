"""IAM checks. IAM is global, so these run once per account, not once per region."""

from __future__ import annotations

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status


@check(
    check_id="IAM-01",
    title="Root user has MFA enabled",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.5",  # verify the number against your pinned version
        nist_800_53_r5="IA-2(1)",
        iso_27001_2022="A.8.5",
        soc2="CC6.1",
    ),
    remediation="Sign in as the root user and register an MFA device (hardware key preferred).",
)
def root_mfa_enabled(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    enabled = summary.get("AccountMFAEnabled", 0) == 1
    return [
        Finding(
            status=Status.PASS if enabled else Status.FAIL,
            resource=f"arn:aws:iam::{ctx.account_id}:root",
            evidence={"AccountMFAEnabled": summary.get("AccountMFAEnabled")},
        )
    ]

@check(
    check_id="IAM-02",
    title="Root has no access keys",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.4",  # verify the number against your pinned version
        nist_800_53_r5="AC-6(5)",
        iso_27001_2022="A.8.2",
        soc2="CC6.1",
    ),
    remediation="Sign in as the root user and delete its access keys." 
    "Use an IAM role or user for programmatic access instead.",
)
def root_has_no_access_keys(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    keys_present = summary["AccountAccessKeysPresent"]
    return [
        Finding(
            status=Status.PASS if keys_present == 0 else Status.FAIL,
            resource=f"arn:aws:iam::{ctx.account_id}:root",
            evidence={"AccountAccessKeysPresent": keys_present},
        )
    ]

# TODO (your turn, Nov 5): IAM-02 "Root user has no access keys"
#   Hint: the same get_account_summary() call has a key called AccountAccessKeysPresent.
#   Controls from the brief: NIST AC-6(5), ISO A.8.2, SOC 2 CC6.1.
# TODO (your turn, Nov 5): IAM-03 "Every user with a console password has MFA"
#   Hint: iam.generate_credential_report() then iam.get_credential_report(); read the CSV.
#   A user "has a console password" when password_enabled is "true"; MFA is mfa_active.
#   Skip the <root_account> row. One Finding per user, so each user is its own evidence.

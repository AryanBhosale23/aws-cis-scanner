"""KMS checks."""

from __future__ import annotations

from botocore.exceptions import ClientError

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status


def _rotatable_customer_keys(kms) -> list[dict]:
    """Customer-managed, symmetric, enabled keys: the only ones CIS expects to rotate."""
    keys = []
    for page in kms.get_paginator("list_keys").paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if (
                meta["KeyManager"] == "CUSTOMER"
                and meta.get("KeySpec") == "SYMMETRIC_DEFAULT"
                and meta["KeyState"] == "Enabled"
                and meta.get("Origin") == "AWS_KMS"
            ):
                keys.append(meta)
    return keys


@check(
    check_id="KMS-19",
    title="Automatic rotation is enabled on customer-managed KMS keys",
    service="kms",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.6",
        nist_800_53_r5="SC-12",
        iso_27001_2022="A.8.24",
        soc2="CC6.1",
    ),
    remediation="Enable automatic rotation on the key.",
)
def key_rotation_enabled(ctx: Context) -> list[Finding]:
    kms = ctx.session.client("kms")
    keys = _rotatable_customer_keys(kms)
    if not keys:
        return [Finding(Status.PASS, f"account:{ctx.account_id}", {"customer_keys_found": 0})]
    findings = []
    for meta in keys:
        try:
            enabled = kms.get_key_rotation_status(KeyId=meta["KeyId"])["KeyRotationEnabled"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            findings.append(Finding(Status.ERROR, meta["Arn"], {"error": code}))
            continue
        findings.append(
            Finding(
                Status.PASS if enabled else Status.FAIL,
                meta["Arn"],
                {"rotation_enabled": enabled},
            )
        )
    return findings
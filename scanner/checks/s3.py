"""S3 checks. Each check returns one result per bucket, so every bucket is its own evidence."""

from __future__ import annotations

from botocore.exceptions import ClientError

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status

PAB_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _bucket_names(ctx: Context) -> list[str]:
    s3 = ctx.session.client("s3")
    pages = s3.get_paginator("list_buckets").paginate()
    return [bucket["Name"] for page in pages for bucket in page["Buckets"]]


def _no_buckets(ctx: Context) -> Finding:
    """With zero buckets there is nothing to fail, but the run still needs to leave evidence."""
    return Finding(
        status=Status.PASS,
        resource=f"account:{ctx.account_id}",
        evidence={"buckets_found": 0},
    )


@check(
    check_id="S3-07",
    title="S3 public access block is on for the account and each bucket",
    service="s3",
    controls=Controls(
        cis=f"{CIS_VERSION}, 3.1.4",  # verify the number against your pinned version
        nist_800_53_r5="AC-3",
        iso_27001_2022="A.8.3",
        soc2="CC6.1",
    ),
    remediation="Enable all four S3 Block Public Access settings on the account and the bucket.",
)
def public_access_block(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []

    # 1) Account level (S3 Control API). A missing configuration means nothing is blocked.
    try:
        cfg = ctx.session.client("s3control").get_public_access_block(AccountId=ctx.account_id)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        cfg = {}
    findings.append(_pab_finding(f"arn:aws:s3:::account/{ctx.account_id}", cfg))

    # 2) Each bucket. One bucket we cannot read must not hide the others, so errors stay local.
    s3 = ctx.session.client("s3")
    for name in _bucket_names(ctx):
        arn = f"arn:aws:s3:::{name}"
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                cfg = {}
            else:
                findings.append(Finding(Status.ERROR, arn, {"error": code}))
                continue
        findings.append(_pab_finding(arn, cfg))
    return findings


def _pab_finding(resource: str, cfg: dict[str, bool]) -> Finding:
    settings = {name: bool(cfg.get(name, False)) for name in PAB_SETTINGS}
    ok = all(settings.values())
    return Finding(Status.PASS if ok else Status.FAIL, resource, settings)


@check(
    check_id="S3-08",
    title="S3 default encryption is enabled",
    service="s3",
    controls=Controls(
        cis=f"{CIS_VERSION}, 3.1.5 (TODO: find the encryption-at-rest recommendation)",
        nist_800_53_r5="SC-28",
        iso_27001_2022="A.8.24",
        soc2="CC6.1",
    ),
    remediation="Enable default encryption on the bucket (SSE-S3 at minimum; SSE-KMS if required).",
)
def default_encryption(ctx: Context) -> list[Finding]:
    s3 = ctx.session.client("s3")
    names = _bucket_names(ctx)
    if not names:
        return [_no_buckets(ctx)]
    findings: list[Finding] = []
    for name in names:
        arn = f"arn:aws:s3:::{name}"
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"][
                "Rules"
            ]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(Finding(Status.FAIL, arn, {"encryption": None}))
            else:
                findings.append(Finding(Status.ERROR, arn, {"error": code}))
            continue
        algos = [
            r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            for r in rules
            if "ApplyServerSideEncryptionByDefault" in r
        ]
        findings.append(
            Finding(Status.PASS if algos else Status.FAIL, arn, {"encryption": algos or None})
        )
    return findings

@check(
    check_id="S3-09",
    title="S3 versioning is enabled",
    service="s3",
    controls=Controls(
        cis=f"{CIS_VERSION}, none",
        nist_800_53_r5="CP-9",
        iso_27001_2022="A.8.13",
        soc2="A1.2",
    ),
    remediation="Turn on versioning so deleted or overwritten objects can be restored.",
)
def versioning_enabled(ctx: Context) -> list[Finding]:
    s3 = ctx.session.client("s3")
    names = _bucket_names(ctx)
    if not names:
        return [_no_buckets(ctx)]
    findings: list[Finding] = []
    for name in names:
        arn = f"arn:aws:s3:::{name}"
        try:
            status = s3.get_bucket_versioning(Bucket=name).get("Status")
        except ClientError as exc:
            findings.append(Finding(Status.ERROR, arn, {"error": exc.response["Error"]["Code"]}))
            continue
        ok = status == "Enabled"
        findings.append(Finding(Status.PASS if ok else Status.FAIL, arn, {"versioning": status}))
    return findings


@check(
    check_id="S3-10",
    title="S3 server access logging is enabled",
    service="s3",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.4 (partial)",
        nist_800_53_r5="AU-12",
        iso_27001_2022="A.8.15",
        soc2="CC7.2",
    ),
    remediation="Turn on server access logging and send the logs to a separate bucket.",
)
def access_logging_enabled(ctx: Context) -> list[Finding]:
    s3 = ctx.session.client("s3")
    names = _bucket_names(ctx)
    if not names:
        return [_no_buckets(ctx)]
    findings: list[Finding] = []
    for name in names:
        arn = f"arn:aws:s3:::{name}"
        try:
            log_config = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        except ClientError as exc:
            findings.append(Finding(Status.ERROR, arn, {"error": exc.response["Error"]["Code"]}))
            continue
        target = log_config["TargetBucket"] if log_config else None
        findings.append(
            Finding(Status.PASS if log_config else Status.FAIL, arn, {"log_target_bucket": target})
        )
    return findings

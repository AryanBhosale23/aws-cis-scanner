"""CloudTrail checks."""

from __future__ import annotations

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status


def _records_all_management_events(trail_client, trail_arn: str) -> bool:
    """True if the trail records management events for both reads and writes."""
    selectors = trail_client.get_event_selectors(TrailName=trail_arn)
    for selector in selectors.get("EventSelectors", []):
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
            return True
    for selector in selectors.get("AdvancedEventSelectors", []):
        fields = {f["Field"]: f for f in selector["FieldSelectors"]}
        management = "Management" in fields.get("eventCategory", {}).get("Equals", [])
        if management and "readOnly" not in fields:
            return True
    return False


@check(
    check_id="CT-11",
    title="A multi-region CloudTrail trail is logging all management events",
    service="cloudtrail",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.1",  # Manual in CIS; this check automates it
        nist_800_53_r5="AU-12",
        iso_27001_2022="A.8.15",
        soc2="CC7.2",
    ),
    remediation="Create a multi-region trail, turn logging on and record all management events.",
)
def multi_region_trail_logging(ctx: Context) -> list[Finding]:
    trail_client = ctx.session.client("cloudtrail")
    trails = trail_client.describe_trails()["trailList"]
    problems: dict[str, list[str]] = {}
    for trail in trails:
        arn = trail["TrailARN"]
        issues = []
        if not trail.get("IsMultiRegionTrail"):
            issues.append("not multi-region")
        if not trail_client.get_trail_status(Name=arn)["IsLogging"]:
            issues.append("not logging")
        if not _records_all_management_events(trail_client, arn):
            issues.append("does not record all management events")
        if not issues:
            return [Finding(Status.PASS, arn, {"trail": trail["Name"], "problems": {}})]
        problems[trail["Name"]] = issues
    evidence = {"trails_found": len(trails), "problems": problems}
    return [Finding(Status.FAIL, f"account:{ctx.account_id}", evidence)]

def _trails(ctx: Context) -> list[dict]:
    return ctx.session.client("cloudtrail").describe_trails()["trailList"]


def _no_trails(ctx: Context) -> Finding:
    """No trail means no logging at all, so the checks on trail settings fail, not pass."""
    return Finding(Status.FAIL, f"account:{ctx.account_id}", {"trails_found": 0})


@check(
    check_id="CT-12",
    title="CloudTrail log file validation is enabled",
    service="cloudtrail",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.2",
        nist_800_53_r5="AU-9",
        iso_27001_2022="A.8.15",
        soc2="CC7.2",
    ),
    remediation="Turn on log file validation for the trail.",
)
def log_file_validation(ctx: Context) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return [_no_trails(ctx)]
    return [
        Finding(
            Status.PASS if trail.get("LogFileValidationEnabled") else Status.FAIL,
            trail["TrailARN"],
            {"log_file_validation": bool(trail.get("LogFileValidationEnabled"))},
        )
        for trail in trails
    ]


@check(
    check_id="CT-13",
    title="CloudTrail logs are encrypted with a KMS key",
    service="cloudtrail",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.5",
        nist_800_53_r5="SC-28",
        iso_27001_2022="A.8.24",
        soc2="CC6.1",
    ),
    remediation="Choose a KMS key for the trail's log file encryption.",
)
def logs_encrypted_with_kms(ctx: Context) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return [_no_trails(ctx)]
    return [
        Finding(
            Status.PASS if trail.get("KmsKeyId") else Status.FAIL,
            trail["TrailARN"],
            {"kms_key_id": trail.get("KmsKeyId")},
        )
        for trail in trails
    ]
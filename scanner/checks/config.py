"""AWS Config checks."""

from __future__ import annotations

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status


@check(
    check_id="CFG-14",
    title="AWS Config is recording all supported resources in this region",
    service="config",
    controls=Controls(
        cis=f"{CIS_VERSION}, 4.3",
        nist_800_53_r5="CM-8",
        iso_27001_2022="A.8.9",
        soc2="CC7.1",
    ),
    remediation="Turn on the AWS Config recorder and record all supported resource types.",
)
def config_recorder_on(ctx: Context) -> list[Finding]:
    config = ctx.session.client("config")
    recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
    if not recorders:
        return [Finding(Status.FAIL, f"account:{ctx.account_id}", {"recorders_found": 0})]
    status_rows = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
    statuses = {row["name"]: row for row in status_rows}
    findings = []
    for recorder in recorders:
        name = recorder["name"]
        status = statuses.get(name, {})
        all_supported = bool(recorder.get("recordingGroup", {}).get("allSupported"))
        recording = bool(status.get("recording"))
        findings.append(
            Finding(
                Status.PASS if all_supported and recording else Status.FAIL,
                f"arn:aws:config:{ctx.region}:{ctx.account_id}:config-recorder/{name}",
                {
                    "all_supported": all_supported,
                    "recording": recording,
                    "last_status": status.get("lastStatus"),
                },
            )
        )
    return findings
"""VPC and security group checks."""

from __future__ import annotations

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status

WORLD = "0.0.0.0/0"


def _admin_rule_open_to_world(permission: dict, port: int) -> bool:
    """True if this one inbound rule lets anyone on the internet reach the given port."""
    protocol = permission.get("IpProtocol")
    if protocol not in ("-1", "tcp", "udp", "6", "17"):
        return False
    if protocol != "-1":  # -1 means all protocols and all ports
        low, high = permission.get("FromPort"), permission.get("ToPort")
        if low is None or high is None or not low <= port <= high:
            return False
    return any(ip_range.get("CidrIp") == WORLD for ip_range in permission.get("IpRanges", []))


def _security_group_findings(ctx: Context, port: int) -> list[Finding]:
    """One result per security group: does any inbound rule open this port to the world?"""
    ec2 = ctx.session.client("ec2")
    pages = ec2.get_paginator("describe_security_groups").paginate()
    findings = []
    for page in pages:
        for group in page["SecurityGroups"]:
            open_rules = [
                f"{p['IpProtocol']} {p.get('FromPort', 'all')}-{p.get('ToPort', 'all')}"
                for p in group["IpPermissions"]
                if _admin_rule_open_to_world(p, port)
            ]
            arn = f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:security-group/{group['GroupId']}"
            findings.append(
                Finding(
                    status=Status.FAIL if open_rules else Status.PASS,
                    resource=arn,
                    evidence={"group_name": group["GroupName"], "open_rules": open_rules},
                )
            )
    return findings


@check(
    check_id="VPC-17",
    title="No security group allows SSH (port 22) from 0.0.0.0/0",
    service="ec2",
    controls=Controls(
        cis=f"{CIS_VERSION}, 6.3",
        nist_800_53_r5="SC-7",
        iso_27001_2022="A.8.20",
        soc2="CC6.6",
    ),
    remediation="Replace the 0.0.0.0/0 source with a trusted range, or delete the rule.",
)
def ssh_not_open_to_world(ctx: Context) -> list[Finding]:
    return _security_group_findings(ctx, 22)


@check(
    check_id="VPC-18",
    title="No security group allows RDP (port 3389) from 0.0.0.0/0",
    service="ec2",
    controls=Controls(
        cis=f"{CIS_VERSION}, 6.3",
        nist_800_53_r5="SC-7",
        iso_27001_2022="A.8.20",
        soc2="CC6.6",
    ),
    remediation="Replace the 0.0.0.0/0 source with a trusted range, or delete the rule.",
)
def rdp_not_open_to_world(ctx: Context) -> list[Finding]:
    return _security_group_findings(ctx, 3389)
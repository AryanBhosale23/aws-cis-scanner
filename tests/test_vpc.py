import boto3

from scanner.checks.vpc import (
    default_security_group_closed,
    flow_logs_enabled,
    rdp_not_open_to_world,
    ssh_not_open_to_world,
)
from scanner.models import Status

WORLD = [{"CidrIp": "0.0.0.0/0"}]
OFFICE = [{"CidrIp": "10.0.0.0/8"}]

# ---- VPC-15 flow logs ---------------------------------------------------------------------


def default_vpc_id():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    return ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"][0][
        "VpcId"
    ]


def make_flow_log(vpc_id, traffic_type="ALL"):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="flow-log-bucket")
    boto3.client("ec2", region_name="us-east-1").create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType=traffic_type,
        LogDestinationType="s3",
        LogDestination="arn:aws:s3:::flow-log-bucket",
    )


def by_vpc(records):
    return {r.resource.rsplit("/", 1)[-1]: r for r in records}


def test_vpc_15_fails_when_the_vpc_has_no_flow_log(ctx):
    [record] = flow_logs_enabled.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"active_flow_logs": []}


def test_vpc_15_passes_when_an_active_flow_log_records_all_traffic(ctx):
    make_flow_log(default_vpc_id(), "ALL")
    [record] = flow_logs_enabled.run(ctx)
    assert record.status is Status.PASS
    assert len(record.evidence["active_flow_logs"]) == 1


def test_vpc_15_fails_when_the_flow_log_only_records_accepted_traffic(ctx):
    make_flow_log(default_vpc_id(), "ACCEPT")
    [record] = flow_logs_enabled.run(ctx)
    assert record.status is Status.FAIL


def test_vpc_15_every_vpc_is_its_own_result(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    other = ec2.create_vpc(CidrBlock="10.5.0.0/16")["Vpc"]["VpcId"]
    make_flow_log(default_vpc_id())
    records = by_vpc(flow_logs_enabled.run(ctx))
    assert records[default_vpc_id()].status is Status.PASS
    assert records[other].status is Status.FAIL


# ---- VPC-16 default security group --------------------------------------------------------


def lock_down_default_groups():
    """Remove every rule from every default group, the state CIS asks for."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    for group in ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]:
        ec2.revoke_security_group_ingress(
            GroupId=group["GroupId"], IpPermissions=group["IpPermissions"]
        )
        ec2.revoke_security_group_egress(
            GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"]
        )


def test_vpc_16_fails_for_an_untouched_default_security_group(ctx):
    [record] = default_security_group_closed.run(ctx)  # a new default group allows all outbound
    assert record.status is Status.FAIL
    assert record.evidence["outbound_rules"] >= 1


def test_vpc_16_fails_when_an_inbound_rule_is_added_to_the_default_group(ctx):
    lock_down_default_groups()
    ec2 = boto3.client("ec2", region_name="us-east-1")
    [group] = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"], IpPermissions=[tcp(80, 80, OFFICE)]
    )
    [record] = default_security_group_closed.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["inbound_rules"] == 1
    assert record.evidence["outbound_rules"] == 0


def test_vpc_16_passes_once_every_rule_is_removed(ctx):
    lock_down_default_groups()
    [record] = default_security_group_closed.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence["inbound_rules"] == 0
    assert record.evidence["outbound_rules"] == 0


def test_vpc_16_ignores_security_groups_that_are_not_the_default(ctx):
    make_group("web-server", tcp(80, 80, WORLD))
    lock_down_default_groups()
    records = default_security_group_closed.run(ctx)
    assert [r.status for r in records] == [Status.PASS]  # only the default group is judged


def test_vpc_16_every_vpc_has_its_own_default_group(ctx):
    boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.6.0.0/16")
    lock_down_default_groups()
    records = default_security_group_closed.run(ctx)
    assert len(records) == 2
    assert all(r.status is Status.PASS for r in records)

def make_group(name, *permissions):
    """Create a security group in the fake AWS with the given inbound rules."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group = ec2.create_security_group(GroupName=name, Description="test group")
    if permissions:
        ec2.authorize_security_group_ingress(
            GroupId=group["GroupId"], IpPermissions=list(permissions)
        )


def tcp(low, high, ranges):
    return {"IpProtocol": "tcp", "FromPort": low, "ToPort": high, "IpRanges": ranges}


def by_name(records):
    return {r.evidence["group_name"]: r for r in records}


# ---- VPC-17 SSH ---------------------------------------------------------------------------


def test_vpc_17_fails_when_ssh_is_open_to_the_world(ctx):
    make_group("open-ssh", tcp(22, 22, WORLD))
    records = by_name(ssh_not_open_to_world.run(ctx))
    assert records["open-ssh"].status is Status.FAIL
    assert records["open-ssh"].evidence["open_rules"] == ["tcp 22-22"]


def test_vpc_17_passes_when_ssh_is_limited_to_a_private_range(ctx):
    make_group("office-ssh", tcp(22, 22, OFFICE))
    records = by_name(ssh_not_open_to_world.run(ctx))
    assert records["office-ssh"].status is Status.PASS


def test_vpc_17_fails_when_a_port_range_includes_22(ctx):
    make_group("wide-range", tcp(0, 3389, WORLD))
    records = by_name(ssh_not_open_to_world.run(ctx))
    assert records["wide-range"].status is Status.FAIL


def test_vpc_17_fails_when_all_traffic_is_open_to_the_world(ctx):
    make_group("allow-all", {"IpProtocol": "-1", "IpRanges": WORLD})
    records = by_name(ssh_not_open_to_world.run(ctx))
    assert records["allow-all"].status is Status.FAIL


def test_vpc_17_ignores_other_ports_open_to_the_world(ctx):
    make_group("web-only", tcp(80, 80, WORLD))
    records = by_name(ssh_not_open_to_world.run(ctx))
    assert records["web-only"].status is Status.PASS


# ---- VPC-18 RDP ---------------------------------------------------------------------------


def test_vpc_18_fails_when_rdp_is_open_to_the_world(ctx):
    make_group("open-rdp", tcp(3389, 3389, WORLD))
    records = by_name(rdp_not_open_to_world.run(ctx))
    assert records["open-rdp"].status is Status.FAIL


def test_vpc_18_does_not_fail_for_ssh_only(ctx):
    make_group("open-ssh", tcp(22, 22, WORLD))
    records = by_name(rdp_not_open_to_world.run(ctx))
    assert records["open-ssh"].status is Status.PASS


def test_vpc_18_every_security_group_is_its_own_result(ctx):
    make_group("group-a", tcp(3389, 3389, WORLD))
    make_group("group-b", tcp(3389, 3389, OFFICE))
    records = by_name(rdp_not_open_to_world.run(ctx))
    assert records["group-a"].status is Status.FAIL
    assert records["group-b"].status is Status.PASS
    assert "default" in records  # the VPC's default group is checked too
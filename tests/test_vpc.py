import boto3

from scanner.checks.vpc import rdp_not_open_to_world, ssh_not_open_to_world
from scanner.models import Status

WORLD = [{"CidrIp": "0.0.0.0/0"}]
OFFICE = [{"CidrIp": "10.0.0.0/8"}]


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
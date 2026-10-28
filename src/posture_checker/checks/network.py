"""Networking and compute checks: security groups and EC2 metadata (CIS section 5)."""

from __future__ import annotations

from ..models import Result, Severity
from ..registry import check
from ._util import paginate

ADMIN_PORTS = (22, 3389)


def _security_groups(ctx, region) -> list[dict]:
    return ctx.cached(
        f"sgs:{region}",
        lambda: paginate(ctx.client("ec2", region), "describe_security_groups", "SecurityGroups"),
    )


def _open_admin_ports(group: dict, cidr_key: str, range_key: str, world: str) -> list[int]:
    ports: set[int] = set()
    for perm in group.get("IpPermissions", []):
        if not any(r.get(cidr_key) == world for r in perm.get(range_key, [])):
            continue
        proto = perm.get("IpProtocol")
        if proto == "-1":
            ports.update(ADMIN_PORTS)
        elif proto in ("tcp", "6"):
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            ports.update(p for p in ADMIN_PORTS if lo <= p <= hi)
    return sorted(ports)


def _admin_port_results(ctx, region, cidr_key, range_key, world):
    for group in _security_groups(ctx, region):
        resource = f"{group['GroupId']} ({group.get('GroupName', '')})"
        ports = _open_admin_ports(group, cidr_key, range_key, world)
        if ports:
            yield Result.fail(resource, f"Allows {world} on port(s) {', '.join(map(str, ports))}.", region)
        else:
            yield Result.ok(resource, f"No admin ports open to {world}.", region)


@check(
    id="sg-admin-ports-ipv4",
    cis="5.2",
    title="No security group allows SSH or RDP from 0.0.0.0/0",
    severity=Severity.HIGH,
    service="ec2",
    regional=True,
    evidence="ec2:DescribeSecurityGroups",
    remediation=(
        "Remove the 0.0.0.0/0 rule for ports 22 and 3389. Use Systems Manager Session Manager, "
        "or restrict the rule to known admin IP ranges."
    ),
)
def sg_admin_ports_ipv4(ctx, region):
    yield from _admin_port_results(ctx, region, "CidrIp", "IpRanges", "0.0.0.0/0")


@check(
    id="sg-admin-ports-ipv6",
    cis="5.3",
    title="No security group allows SSH or RDP from ::/0",
    severity=Severity.HIGH,
    service="ec2",
    regional=True,
    evidence="ec2:DescribeSecurityGroups",
    remediation="Remove the ::/0 rule for ports 22 and 3389, or restrict it to known admin IPv6 ranges.",
)
def sg_admin_ports_ipv6(ctx, region):
    yield from _admin_port_results(ctx, region, "CidrIpv6", "Ipv6Ranges", "::/0")


@check(
    id="sg-default-restricts-all",
    cis="5.4",
    title="Default security groups restrict all traffic",
    severity=Severity.LOW,
    service="ec2",
    regional=True,
    evidence="ec2:DescribeSecurityGroups",
    remediation=(
        "Remove all inbound and outbound rules from each VPC's default security group "
        "and use purpose-built groups instead."
    ),
)
def sg_default_restricts_all(ctx, region):
    for group in _security_groups(ctx, region):
        if group.get("GroupName") != "default":
            continue
        rules = len(group.get("IpPermissions", [])) + len(group.get("IpPermissionsEgress", []))
        resource = f"{group['GroupId']} ({group.get('VpcId', '-')})"
        if rules:
            yield Result.fail(resource, f"Default group has {rules} rule(s).", region)
        else:
            yield Result.ok(resource, "Default group has no rules.", region)


@check(
    id="ec2-imdsv2",
    cis="5.6",
    title="EC2 instances require IMDSv2",
    severity=Severity.MEDIUM,
    service="ec2",
    regional=True,
    evidence="ec2:DescribeInstances",
    remediation="Set the instance metadata option HttpTokens to 'required' (IMDSv2 only).",
)
def ec2_imdsv2(ctx, region):
    ec2 = ctx.client("ec2", region)
    for reservation in paginate(ec2, "describe_instances", "Reservations"):
        for inst in reservation["Instances"]:
            if inst.get("State", {}).get("Name") == "terminated":
                continue
            tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")
            if tokens == "required":
                yield Result.ok(inst["InstanceId"], "IMDSv2 is required.", region)
            else:
                yield Result.fail(inst["InstanceId"], "IMDSv1 is still allowed.", region)

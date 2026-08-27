"""EC2 보안그룹 스캐너 테스트 (moto).

케이스:
1. 22 오픈 + 인스턴스 연결 + 퍼블릭 IP → HIGH, EC2-SG-001
2. 포트 범위(3000-4000)가 3306 포함 → 탐지 (범위 포함 판정)
3. IpProtocol=-1 전포트 오픈 → EC2-SG-002, 등급 상향
4. ::/0 IPv6 오픈 → 탐지
5. 사내망(10.0.0.0/8) 소스 → 미탐지 (오탐 방지)
6. 80 포트 오픈 → 미탐지 (스코프 외 포트)
7. 미연결 SG → LOW
"""

import boto3
import pytest
from moto import mock_aws

from cspm.core.finding import Severity
from cspm.scanners.ec2_security_group import Ec2SecurityGroupScanner

REGION = "ap-northeast-2"


@pytest.fixture
def aws():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        yield session, ec2, vpc_id, subnet_id


def make_sg(ec2, vpc_id, name, permissions):
    sg_id = ec2.create_security_group(
        GroupName=name, Description=name, VpcId=vpc_id
    )["GroupId"]
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permissions)
    return sg_id


def attach_instance(ec2, subnet_id, sg_id, public=False):
    ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        NetworkInterfaces=[{
            "DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
            "AssociatePublicIpAddress": public,
        }],
    )


def scan(session):
    return Ec2SecurityGroupScanner(session, REGION).scan()


def findings_for(findings, sg_id):
    return [f for f in findings if f.resource_id == sg_id]


TCP_22_OPEN = [{
    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
}]


def test_ssh_open_attached_public_is_high(aws):
    session, ec2, vpc_id, subnet_id = aws
    sg_id = make_sg(ec2, vpc_id, "ssh-open", TCP_22_OPEN)
    attach_instance(ec2, subnet_id, sg_id, public=True)

    result = findings_for(scan(session), sg_id)
    assert len(result) == 1
    f = result[0]
    assert f.check_id == "EC2-SG-001"
    assert f.severity == Severity.HIGH
    assert f.evidence["public_ips"]


def test_port_range_containment_detects_3306(aws):
    session, ec2, vpc_id, _ = aws
    sg_id = make_sg(ec2, vpc_id, "range-open", [{
        "IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }])
    result = findings_for(scan(session), sg_id)
    assert len(result) == 1
    assert 3306 in result[0].evidence["rules"][0]["ports"]


def test_all_protocol_open_is_separate_check_and_bumped(aws):
    session, ec2, vpc_id, subnet_id = aws
    sg_id = make_sg(ec2, vpc_id, "all-open", [{
        "IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }])
    attach_instance(ec2, subnet_id, sg_id, public=True)

    result = findings_for(scan(session), sg_id)
    assert len(result) == 1
    f = result[0]
    assert f.check_id == "EC2-SG-002"
    assert f.severity == Severity.CRITICAL  # HIGH에서 한 등급 상향


def test_ipv6_any_source_detected(aws):
    session, ec2, vpc_id, _ = aws
    sg_id = make_sg(ec2, vpc_id, "v6-open", [{
        "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }])
    assert len(findings_for(scan(session), sg_id)) == 1


def test_private_source_not_detected(aws):
    session, ec2, vpc_id, _ = aws
    sg_id = make_sg(ec2, vpc_id, "internal", [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }])
    assert findings_for(scan(session), sg_id) == []


def test_non_risky_port_not_detected(aws):
    session, ec2, vpc_id, _ = aws
    sg_id = make_sg(ec2, vpc_id, "web", [{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }])
    assert findings_for(scan(session), sg_id) == []


def test_unattached_sg_is_low(aws):
    session, ec2, vpc_id, _ = aws
    sg_id = make_sg(ec2, vpc_id, "unattached", TCP_22_OPEN)
    result = findings_for(scan(session), sg_id)
    assert len(result) == 1
    assert result[0].severity == Severity.LOW

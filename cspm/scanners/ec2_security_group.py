"""[기능 3] EC2 보안그룹 오픈 포트 탐지.

판단 기준 (2026-07-27 확정 — 벤더 레퍼런스 기반):
- 매칭 (Prowler check_security_group 방식):
  * 인바운드 소스가 0.0.0.0/0 또는 ::/0
  * TCP이고 FromPort~ToPort 범위가 위험 포트를 '포함' (단순 FromPort 비교 아님)
  * IpProtocol == "-1" (전 포트/프로토콜 허용)은 별도 check_id로 분리, 더 심각하게 판정
- severity 차등 (Wiz 유효 노출 / Trusted Advisor 티어 방식):
  * SG가 ENI에 연결 + 해당 ENI가 퍼블릭 IP 보유 → 실제 노출     → HIGH
  * SG가 ENI에 연결 + 퍼블릭 IP 없음        → 내부만 노출   → MEDIUM
  * SG가 어디에도 연결 안 됨               → 하이진 이슈   → LOW
    (Prowler는 기본 설정에서 미사용 SG 스킵하지만, 우리는 LOW로 리포트)
  * 전 포트 오픈(-1)은 각 단계 한 등급 상향 (CRITICAL / HIGH / MEDIUM)

레퍼런스:
- AWS Security Hub EC2.19 (고위험 포트 목록·0.0.0.0/0 판정)
- Prowler ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 + lib/security_groups.py
- AWS Trusted Advisor "Security Groups - Specific Ports Unrestricted" (위험도 티어)
- Wiz effective exposure (설정 오픈 vs 실제 노출 구분)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cspm.core.finding import Finding, Severity
from cspm.core.scanner import BaseScanner

# 스코프 확정 포트 (Security Hub EC2.19 전체 목록 24개 중 프로젝트 스코프 4개)
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}

ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"


def _open_sources(perm: dict[str, Any]) -> list[str]:
    """규칙에서 전세계 오픈(0.0.0.0/0, ::/0) 소스만 추출."""
    sources = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == ANY_IPV4]
    sources += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == ANY_IPV6]
    return sources


def _matched_risky_ports(perm: dict[str, Any]) -> list[int]:
    """TCP 규칙의 포트 범위가 위험 포트를 포함하는지 (범위 포함 판정)."""
    if perm.get("IpProtocol") not in ("tcp",):
        return []
    from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
    if from_port is None or to_port is None:
        return []
    return sorted(p for p in RISKY_PORTS if from_port <= p <= to_port)


class Ec2SecurityGroupScanner(BaseScanner):
    name = "ec2"
    service = "ec2"
    description = "0.0.0.0/0 + 위험포트 오픈 보안그룹 탐지"

    N2SF_AREA = "분리·격리"
    CNAPP = "CSPM"

    def scan(self) -> list[Finding]:
        ec2 = self.session.client("ec2", region_name=self.region)
        sg_enis = self._map_sg_to_enis(ec2)

        findings: list[Finding] = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                findings.extend(self._check_sg(sg, sg_enis.get(sg["GroupId"], [])))
        return findings

    # --- 내부 로직 ---

    def _map_sg_to_enis(self, ec2) -> dict[str, list[dict[str, Any]]]:
        """SG ID → 연결된 ENI 목록 (유효 노출 판정용)."""
        mapping: dict[str, list[dict[str, Any]]] = defaultdict(list)
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page["NetworkInterfaces"]:
                for group in eni.get("Groups", []):
                    mapping[group["GroupId"]].append(eni)
        return mapping

    @staticmethod
    def _exposure(enis: list[dict[str, Any]]) -> tuple[bool, list[str]]:
        """(연결 여부, 퍼블릭 IP 목록)"""
        public_ips = [
            eni["Association"]["PublicIp"]
            for eni in enis
            if eni.get("Association", {}).get("PublicIp")
        ]
        return bool(enis), public_ips

    @staticmethod
    def _severity(attached: bool, public: bool, all_ports: bool) -> Severity:
        base = (
            Severity.HIGH if public else Severity.MEDIUM if attached else Severity.LOW
        )
        if not all_ports:
            return base
        bump = {
            Severity.HIGH: Severity.CRITICAL,
            Severity.MEDIUM: Severity.HIGH,
            Severity.LOW: Severity.MEDIUM,
        }
        return bump[base]

    def _check_sg(self, sg: dict[str, Any], enis: list[dict[str, Any]]) -> list[Finding]:
        sg_id, sg_name = sg["GroupId"], sg.get("GroupName", "")
        attached, public_ips = self._exposure(enis)

        risky_rules: list[dict[str, Any]] = []   # 위험 포트 오픈 규칙
        all_port_rules: list[dict[str, Any]] = []  # 전 포트/프로토콜 오픈 규칙

        for perm in sg.get("IpPermissions", []):
            sources = _open_sources(perm)
            if not sources:
                continue
            if perm.get("IpProtocol") == "-1":
                all_port_rules.append({"sources": sources})
                continue
            ports = _matched_risky_ports(perm)
            if ports:
                risky_rules.append(
                    {
                        "sources": sources,
                        "ports": ports,
                        "range": f"{perm.get('FromPort')}-{perm.get('ToPort')}",
                    }
                )

        findings = []
        exposure_note = (
            f"퍼블릭 IP {public_ips}로 실제 인터넷 노출" if public_ips
            else "ENI 연결됨(프라이빗)" if attached
            else "미연결 SG(설정만 위험)"
        )
        evidence_base = {
            "group_name": sg_name,
            "attached_eni_count": len(enis),
            "public_ips": public_ips,
        }

        if all_port_rules:
            findings.append(
                Finding(
                    check_id="EC2-SG-002",
                    title=f"보안그룹 {sg_id}: 전 포트/프로토콜 인터넷 오픈",
                    severity=self._severity(attached, bool(public_ips), all_ports=True),
                    service=self.service,
                    resource_id=sg_id,
                    region=self.region,
                    description=f"IpProtocol=-1 로 모든 트래픽이 인터넷에 오픈됨. {exposure_note}.",
                    evidence={**evidence_base, "rules": all_port_rules},
                    remediation=(
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--ip-permissions 'IpProtocol=-1,IpRanges=[{{CidrIp=0.0.0.0/0}}]'"
                    ),
                    n2sf_area=self.N2SF_AREA,
                    cnapp_category=self.CNAPP,
                )
            )

        if risky_rules:
            ports = sorted({p for r in risky_rules for p in r["ports"]})
            port_names = ", ".join(f"{p}({RISKY_PORTS[p]})" for p in ports)
            findings.append(
                Finding(
                    check_id="EC2-SG-001",
                    title=f"보안그룹 {sg_id}: 위험 포트 {port_names} 인터넷 오픈",
                    severity=self._severity(attached, bool(public_ips), all_ports=False),
                    service=self.service,
                    resource_id=sg_id,
                    region=self.region,
                    description=f"0.0.0.0/0(또는 ::/0)에서 {port_names} 접근 가능. {exposure_note}.",
                    evidence={**evidence_base, "rules": risky_rules},
                    remediation=(
                        "해당 인바운드 규칙의 소스를 특정 IP 대역으로 제한하거나 삭제. 예: "
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--protocol tcp --port {ports[0]} --cidr 0.0.0.0/0"
                    ),
                    n2sf_area=self.N2SF_AREA,
                    cnapp_category=self.CNAPP,
                )
            )
        return findings

"""골격 검증 테스트: 스키마 직렬화 + 스캐너 레지스트리."""

from cspm.core.finding import Finding, Severity
from cspm.scanners import SCANNERS


def test_finding_to_dict():
    f = Finding(
        check_id="EC2-SG-001",
        title="테스트",
        severity=Severity.HIGH,
        service="ec2",
        resource_id="sg-123",
        region="ap-northeast-2",
        description="테스트용",
    )
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["check_id"] == "EC2-SG-001"
    assert "detected_at" in d


def test_registry_has_four_scanners():
    assert set(SCANNERS) == {"ec2", "s3", "iam", "cloudtrail"}

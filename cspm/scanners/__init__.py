"""스캐너 레지스트리. 구현 순서: ec2 → s3 → iam → cloudtrail."""

from cspm.scanners.ec2_security_group import Ec2SecurityGroupScanner
from cspm.scanners.s3_misconfig import S3MisconfigScanner
from cspm.scanners.iam_overprivilege import IamOverprivilegeScanner
from cspm.scanners.cloudtrail_anomaly import CloudTrailAnomalyScanner

SCANNERS = {
    s.name: s
    for s in (
        Ec2SecurityGroupScanner,
        S3MisconfigScanner,
        IamOverprivilegeScanner,
        CloudTrailAnomalyScanner,
    )
}

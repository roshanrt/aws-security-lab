"""Offline unit tests for the detection rules. No AWS or LocalStack needed.

    py -m unittest discover -s enterprise\\tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "detection"))
import detector  # noqa: E402

CFG = {
    "trusted_deployers": ["arn:aws:iam::444444444444:root"],
    "secret_allowlist": {"prod/db/master": ["app-prod-api", "lz-break-glass"]},
}
CI = {"arn": "arn:aws:sts::444444444444:assumed-role/lz-ci-deployer/lab-session"}


def ev(name, request=None, identity=None, **extra):
    return {"eventID": f"id-{name}", "eventName": name, "userIdentity": identity or CI,
            "requestParameters": request or {}, "recipientAccountId": "444444444444", **extra}


def rules(events):
    return sorted({f["rule_id"] for f in detector.evaluate(events, CFG)})


class RuleTests(unittest.TestCase):
    def test_trail_tamper(self):
        self.assertEqual(rules([ev("StopLogging", {"name": "lz-trail"})]), ["ENT-001"])

    def test_iam_change_and_admin_attach(self):
        e = ev("AttachRolePolicy", {"roleName": "x", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        self.assertEqual(rules([e]), ["ENT-002", "ENT-003"])

    def test_sg_open_cloudtrail_and_localstack_shapes(self):
        real = {"groupId": "sg-0abc", "ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
        local = {"GroupId": "sg-0abc", "IpProtocol": "tcp", "CidrIp": "0.0.0.0/0"}
        self.assertEqual(rules([ev("AuthorizeSecurityGroupIngress", real)]), ["ENT-004"])
        self.assertEqual(rules([ev("AuthorizeSecurityGroupIngress", local)]), ["ENT-004"])
        self.assertEqual(rules([ev("AuthorizeSecurityGroupIngress", {"GroupId": "sg-0abc", "CidrIp": "10.0.0.0/8"})]), [])

    def test_public_bucket_policy(self):
        public = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}'
        scoped = '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}'
        self.assertEqual(rules([ev("PutBucketPolicy", {"bucketName": "b", "bucketPolicy": public})]), ["ENT-005"])
        self.assertEqual(rules([ev("PutBucketPolicy", {"bucketName": "b", "bucketPolicy": scoped})]), [])
        self.assertEqual(rules([ev("DeletePublicAccessBlock", {"bucketName": "b"})]), ["ENT-005"])
        # LocalStack shape: policy text not recorded -> fail closed
        self.assertEqual(rules([ev("PutBucketPolicy", {"bucketName": "b", "policy": ""})]), ["ENT-005"])

    def test_kms_destroy(self):
        self.assertEqual(rules([ev("ScheduleKeyDeletion", {"keyId": "k"})]), ["ENT-006"])

    def test_secret_allowlist(self):
        app = {"arn": "arn:aws:sts::444444444444:assumed-role/app-prod-api/fn"}
        self.assertEqual(rules([ev("GetSecretValue", {"secretId": "prod/db/master"}, app)]), [])
        self.assertEqual(rules([ev("GetSecretValue", {"secretId": "prod/db/master"})]), ["ENT-007"])
        self.assertEqual(rules([ev("GetSecretValue", {"secretId": "unlisted"}, app)]), ["ENT-007"])

    def test_break_glass(self):
        e = ev("AssumeRole", {"roleArn": "arn:aws:iam::444444444444:role/lz-break-glass"})
        self.assertEqual(rules([e]), ["ENT-008"])

    def test_trusted_and_own_activity_is_ignored(self):
        root = {"arn": "arn:aws:iam::444444444444:root"}
        response = {"arn": "arn:aws:sts::444444444444:assumed-role/lz-security-response/lz-detector"}
        self.assertEqual(rules([ev("StopLogging", {"name": "t"}, root)]), [])
        self.assertEqual(rules([ev("CreateRole", {"roleName": "r"}, response)]), [])

    def test_principal_name(self):
        self.assertEqual(detector.principal_name({"userIdentity": CI}), "lz-ci-deployer")
        self.assertEqual(detector.principal_name({"userIdentity": {"arn": "arn:aws:iam::1:user/lab-only/lab-bootstrap"}}), "lab-bootstrap")

    def test_principal_label_never_starts_with_arn(self):
        self.assertEqual(detector.principal_label({"userIdentity": CI}), f"lz-ci-deployer ({CI['arn']})")
        root = {"userIdentity": {"arn": "arn:aws:iam::606578970288:root"}}
        self.assertEqual(detector.principal_label(root), "root (arn:aws:iam::606578970288:root)")

    def test_outcome_and_dedupe_key(self):
        f = detector.evaluate([ev("StopLogging", {"name": "t"}, errorCode="AccessDenied")], CFG)[0]
        self.assertEqual(f["outcome"], "failed (AccessDenied)")
        self.assertEqual(f["pk"], "ENT-001#id-StopLogging")


if __name__ == "__main__":
    unittest.main()

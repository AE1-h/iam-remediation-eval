"""
Unit tests for the Deterministic IAM Oracle.
Verifies exact semantics of AWS IAM and GCP IAM policy evaluations.
"""

import unittest
from oracle.evaluator import DeterministicOracle, parse_aws_policy
from oracle.models import PermissionCheck, TestCase
from oracle.verdict import VerdictStatus


class TestDeterministicOracle(unittest.TestCase):
    def setUp(self):
        self.oracle = DeterministicOracle()

    def test_aws_explicit_deny_overrides_allow(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowS3", "Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                {"Sid": "DenyVault", "Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::vault/*"},
            ],
        }
        case = TestCase(
            case_id="synthetic_deny_test",
            title="Explicit Deny Test",
            cloud="aws",
            initial_policy=policy,
            must_deny=[
                PermissionCheck(action="s3:GetObject", resource="arn:aws:s3:::vault/secret.txt")
            ],
            must_allow=[
                PermissionCheck(action="s3:GetObject", resource="arn:aws:s3:::public/image.png")
            ],
        )
        res = self.oracle.evaluate(policy, case)
        self.assertEqual(res.verdict, VerdictStatus.CORRECT)
        self.assertTrue(res.is_safe)
        self.assertTrue(res.is_intact)

    def test_aws_default_deny_when_unmatched(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowEC2", "Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
            ],
        }
        case = TestCase(
            case_id="synthetic_default_deny",
            title="Default Deny Test",
            cloud="aws",
            initial_policy=policy,
            must_deny=[
                PermissionCheck(action="iam:PassRole", resource="*")
            ],
            must_allow=[
                PermissionCheck(action="s3:GetObject", resource="arn:aws:s3:::bucket/file.txt")
            ],
        )
        res = self.oracle.evaluate(policy, case)
        # S3 GetObject is implicitly denied -> BROKEN operations check
        # iam:PassRole is implicitly denied -> SAFE security check
        self.assertEqual(res.verdict, VerdictStatus.BROKEN)
        self.assertTrue(res.is_safe)
        self.assertFalse(res.is_intact)

    def test_aws_wildcard_case_insensitivity(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "MixedCase", "Effect": "Allow", "Action": "EC2:describeinstances", "Resource": "*"}
            ],
        }
        case = TestCase(
            case_id="case_insensitivity_test",
            title="Case Insensitivity Test",
            cloud="aws",
            initial_policy=policy,
            must_deny=[],
            must_allow=[
                PermissionCheck(action="ec2:DescribeInstances", resource="*")
            ],
        )
        res = self.oracle.evaluate(policy, case)
        self.assertEqual(res.verdict, VerdictStatus.CORRECT)

    def test_aws_conditions_matching(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedKey",
                    "Effect": "Allow",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "arn:aws:iam::123456789012:user/*",
                    "Condition": {
                        "StringEquals": {"aws:username": "alice"}
                    }
                }
            ],
        }
        # When context matches username
        case_match = TestCase(
            case_id="cond_match",
            title="Condition Match",
            cloud="aws",
            initial_policy=policy,
            must_deny=[],
            must_allow=[
                PermissionCheck(
                    action="iam:CreateAccessKey",
                    resource="arn:aws:iam::123456789012:user/alice",
                    context={"aws:username": "alice"}
                )
            ]
        )
        res_match = self.oracle.evaluate(policy, case_match)
        self.assertEqual(res_match.verdict, VerdictStatus.CORRECT)

        # When context differs or is missing
        case_unmatched = TestCase(
            case_id="cond_unmatched",
            title="Condition Unmatched",
            cloud="aws",
            initial_policy=policy,
            must_deny=[
                PermissionCheck(
                    action="iam:CreateAccessKey",
                    resource="arn:aws:iam::123456789012:user/admin",
                    context={"aws:username": "other"}
                )
            ],
            must_allow=[]
        )
        res_unmatched = self.oracle.evaluate(policy, case_unmatched)
        self.assertEqual(res_unmatched.verdict, VerdictStatus.CORRECT)

    def test_invalid_json_and_syntax(self):
        case = TestCase(
            case_id="syntax_test",
            title="Syntax Test",
            cloud="aws",
            initial_policy={},
            must_deny=[],
            must_allow=[]
        )
        res1 = self.oracle.evaluate("not a valid json {", case)
        self.assertEqual(res1.verdict, VerdictStatus.INVALID)

        res2 = self.oracle.evaluate({"NoStatementKey": True}, case)
        self.assertEqual(res2.verdict, VerdictStatus.INVALID)

        res3 = self.oracle.evaluate({"Statement": [{"Effect": "InvalidEffect"}]}, case)
        self.assertEqual(res3.verdict, VerdictStatus.INVALID)

    def test_gcp_role_binding_evaluation(self):
        gcp_policy = {
            "bindings": [
                {
                    "role": "roles/cloudfunctions.viewer",
                    "members": ["user:analyst@example.com"]
                }
            ]
        }
        case = TestCase(
            case_id="gcp_test",
            title="GCP Evaluation Test",
            cloud="gcp",
            initial_policy=gcp_policy,
            must_deny=[
                PermissionCheck(
                    action="cloudfunctions.functions.create",
                    resource="projects/p/locations/l/functions/f",
                    context={"member": "user:analyst@example.com"}
                )
            ],
            must_allow=[
                PermissionCheck(
                    action="cloudfunctions.functions.get",
                    resource="projects/p/locations/l/functions/f",
                    context={"member": "user:analyst@example.com"}
                )
            ]
        )
        res = self.oracle.evaluate(gcp_policy, case)
        self.assertEqual(res.verdict, VerdictStatus.CORRECT)
        self.assertTrue(res.is_safe)
        self.assertTrue(res.is_intact)


if __name__ == "__main__":
    unittest.main()

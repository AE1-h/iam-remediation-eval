"""Expected outcomes for supported semantics and explicit refusal boundaries."""
import unittest

from oracle.evaluator import DeterministicOracle, _check_condition, _match_wildcard
from oracle.models import PermissionCheck, TestCase
from oracle.verdict import VerdictStatus


class OracleRegressions(unittest.TestCase):
    def evaluate(self, policy, cloud="aws", deny=None, allow=None):
        return DeterministicOracle().evaluate(policy, TestCase(
            "regression", "Regression", cloud, {}, deny or [], allow or []))

    def statement(self, **overrides):
        return {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", **overrides}

    def test_unsupported_operators_invalid_on_allow_and_deny(self):
        for effect in ("Allow", "Deny"):
            for op in ("Bool", "IpAddress", "StringNotLike", "NumericEquals",
                       "StringEqualsIfExists", "ForAnyValue:StringEquals", "bogusStringEquals"):
                with self.subTest(effect=effect, operator=op):
                    policy = {"Statement": [self.statement(Effect=effect, Condition={op: {"key": "true"}})]}
                    result = self.evaluate(policy, allow=[PermissionCheck("s3:GetObject", "*", context={"key": "true"})])
                    self.assertEqual(result.verdict, VerdictStatus.INVALID)
                    self.assertIn(op, result.error_message)

    def test_unsupported_condition_rejected_even_if_unreachable(self):
        for statements in ([self.statement(Effect="Deny"), self.statement(Condition={"Bool": {"key": "true"}})],
                           [self.statement(Action="ec2:*", Condition={"Bool": {"key": "true"}})]):
            self.assertEqual(self.evaluate({"Statement": statements}).verdict, VerdictStatus.INVALID)

    def test_direct_condition_helper_raises(self):
        with self.assertRaisesRegex(ValueError, "Unsupported condition operator"):
            _check_condition({"Bool": {"aws:SecureTransport": "true"}}, {"aws:SecureTransport": "true"})

    def test_malformed_conditions_are_invalid(self):
        for condition in (None, [], "bad", {"StringEquals": []}, {"StringEquals": {}},
                          {"StringEquals": {"k": []}}, {"StringEquals": {"k": 1}}):
            with self.subTest(condition=condition):
                self.assertEqual(self.evaluate({"Statement": [self.statement(Condition=condition)]}).verdict, VerdictStatus.INVALID)

    def test_negation_uses_nor_and_missing_key_is_true(self):
        condition = {"StringNotEquals": {"key": ["alice", "bob"]}}
        self.assertFalse(_check_condition(condition, {"key": "alice"}))
        self.assertTrue(_check_condition(condition, {"key": "carol"}))
        self.assertTrue(_check_condition(condition, {}))

    def test_condition_keys_ignore_case_values_do_not(self):
        condition = {"StringEquals": {"AWS:username": "Alice"}}
        self.assertTrue(_check_condition(condition, {"aws:UserName": "Alice"}))
        self.assertFalse(_check_condition(condition, {"aws:username": "alice"}))
        self.assertFalse(_check_condition(condition, {}))

    def test_condition_keys_and_operators_are_conjoined(self):
        condition = {"StringEquals": {"a": ["1", "2"], "b": "3"}, "StringLike": {"c": "x*"}}
        self.assertTrue(_check_condition(condition, {"a": "2", "b": "3", "c": "xyz"}))
        self.assertFalse(_check_condition(condition, {"a": "2", "b": "4", "c": "xyz"}))

    def test_arn_equals_supports_wildcards(self):
        for op in ("ArnEquals", "ArnLike"):
            self.assertTrue(_check_condition({op: {"arn": "arn:aws:s3:::bucket/*"}}, {"arn": "arn:aws:s3:::bucket/a"}))

    def test_conditional_deny_is_gated(self):
        policy = {"Statement": [self.statement(), self.statement(Effect="Deny", Condition={"StringEquals": {"user": "bad"}})]}
        result = self.evaluate(policy,
            deny=[PermissionCheck("s3:GetObject", "*", context={"user": "bad"})],
            allow=[PermissionCheck("s3:GetObject", "*", context={"user": "good"})])
        self.assertEqual(result.verdict, VerdictStatus.CORRECT)

    def test_resource_case_and_literal_brackets(self):
        self.assertFalse(_match_wildcard("bucket/A", "bucket/a", True))
        self.assertFalse(_match_wildcard("bucket/[ab]", "bucket/a", True))
        self.assertTrue(_match_wildcard("bucket/[ab]", "bucket/[ab]", True))
        self.assertTrue(_match_wildcard("bucket/?/*", "bucket/a/x/y", True))
        self.assertFalse(_match_wildcard("bucket/?", "bucket/ab", True))

    def test_unsupported_policy_features_rejected(self):
        for extra in ({"NotAction": "iam:*"}, {"NotResource": "*"}, {"Principal": "*"},
                      {"Resource": "arn:aws:iam::123:user/${aws:username}"},
                      {"Condition": {"StringEquals": {"k": "${aws:username}"}}}):
            self.assertEqual(self.evaluate({"Statement": [self.statement(**extra)]}).verdict, VerdictStatus.INVALID)

    def test_invalid_aws_fields_not_coerced(self):
        for field in ("Action", "Resource"):
            for value in ([], [1], None, {}, ""):
                self.assertEqual(self.evaluate({"Statement": [self.statement(**{field: value})]}).verdict, VerdictStatus.INVALID)
            stmt = self.statement()
            del stmt[field]
            self.assertEqual(self.evaluate({"Statement": [stmt]}).verdict, VerdictStatus.INVALID)

    def test_unsupported_context_rejected(self):
        for context in ({"k": ["a", "b"]}, {"k": "a", "K": "b"}):
            self.assertEqual(self.evaluate({"Statement": []}, allow=[PermissionCheck("s3:GetObject", "*", context=context)]).verdict, VerdictStatus.INVALID)

    def test_both_unsafe_and_broken_are_retained(self):
        result = self.evaluate({"Statement": [self.statement()]},
            deny=[PermissionCheck("s3:GetObject", "*")], allow=[PermissionCheck("s3:PutObject", "*")])
        self.assertEqual(result.verdict, VerdictStatus.UNSAFE)
        self.assertFalse(result.is_safe)
        self.assertFalse(result.is_intact)
        self.assertEqual(len(result.broken_violations), 1)

    def test_gcp_malformed_roots_bindings_and_unknown_roles(self):
        for policy in ("null", "[]", "1", '{"bindings":[null]}', {"bindings": [1]},
                       {"bindings": [{"role": "roles/unknown", "members": ["user:a"]}]},
                       {"bindings": [{"role": "roles/viewer", "members": "user:a"}]},
                       {"bindings": [{"role": "roles/viewer", "members": ["user:a"], "condition": {}}]}):
            with self.subTest(policy=policy):
                self.assertEqual(self.evaluate(policy, "gcp").verdict, VerdictStatus.INVALID)

    def test_gcp_member_scope_and_case_sensitive_permissions(self):
        policy = {"bindings": [{"role": "roles/cloudfunctions.viewer", "members": ["user:alice@example.com"]}]}
        result = self.evaluate(policy, "gcp",
            deny=[PermissionCheck("cloudfunctions.functions.get", "*", context={"member": "user:bob@example.com"}),
                  PermissionCheck("CLOUDFUNCTIONS.functions.get", "*", context={"member": "user:alice@example.com"})],
            allow=[PermissionCheck("cloudfunctions.functions.get", "*", context={"member": "user:alice@example.com"})])
        self.assertEqual(result.verdict, VerdictStatus.CORRECT)

    def test_gcp_ambiguous_members_rejected(self):
        for member in ("allUsers", "allAuthenticatedUsers", "user:*", "group:team@example.com"):
            self.assertEqual(self.evaluate({"bindings": [{"role": "roles/viewer", "members": [member]}]}, "gcp").verdict, VerdictStatus.INVALID)
        self.assertEqual(self.evaluate({"bindings": []}, "gcp", allow=[PermissionCheck("storage.objects.get", "*")]).verdict, VerdictStatus.INVALID)

    def test_unknown_cloud_rejected(self):
        self.assertEqual(self.evaluate({"Statement": []}, "azure").verdict, VerdictStatus.INVALID)

    def test_duplicate_json_keys_and_non_json_constants_rejected(self):
        for cloud, raw in (("aws", '{"Statement": [], "Statement": []}'),
                           ("aws", '{"Statement": [], "Id": NaN}'),
                           ("gcp", '{"bindings": [], "bindings": []}')):
            self.assertEqual(self.evaluate(raw, cloud).verdict, VerdictStatus.INVALID)

    def test_explicit_deny_independent_of_statement_order(self):
        statements = [self.statement(), self.statement(Effect="Deny")]
        for ordered in (statements, list(reversed(statements))):
            self.assertEqual(self.evaluate({"Statement": ordered}, deny=[PermissionCheck("s3:GetObject", "*")]).verdict, VerdictStatus.CORRECT)

    def test_old_case05_reference_is_broken_for_rotation(self):
        from pathlib import Path
        case = TestCase.load_from_dir(Path(__file__).resolve().parent.parent / "cases" / "05-createaccesskey")
        old_policy = {"Statement": [{"Effect": "Allow", "Action": ["iam:GetUser", "iam:ListAccessKeys"],
                                     "Resource": "arn:aws:iam::123456789012:user/app-worker"}]}
        result = DeterministicOracle().evaluate(old_policy, case)
        self.assertEqual(result.verdict, VerdictStatus.BROKEN)
        self.assertEqual({c.action for c in result.broken_violations}, {"iam:CreateAccessKey", "iam:DeleteAccessKey"})

"""
Oracle module root: exports the evaluator, models, and verdict types.
"""

from oracle.evaluator import DeterministicOracle, parse_aws_policy
from oracle.models import IAMPolicy, PermissionCheck, Statement, TestCase
from oracle.verdict import CheckDetail, EvaluationResult, VerdictStatus

__all__ = [
    "DeterministicOracle",
    "IAMPolicy",
    "Statement",
    "PermissionCheck",
    "TestCase",
    "EvaluationResult",
    "CheckDetail",
    "VerdictStatus",
    "parse_aws_policy",
]

"""
Deterministic verdict definitions and evaluation output models.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class VerdictStatus(str, Enum):
    CORRECT = "correct"
    UNSAFE = "unsafe"
    BROKEN = "broken"
    INVALID = "invalid"


@dataclass
class CheckDetail:
    action: str
    resource: str
    allowed: bool
    description: str = ""
    matched_statement: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "resource": self.resource,
            "allowed": self.allowed,
            "description": self.description,
            "matched_statement": self.matched_statement,
            "reason": self.reason,
        }


@dataclass
class EvaluationResult:
    case_id: str
    verdict: VerdictStatus
    is_safe: bool
    is_intact: bool
    unsafe_violations: List[CheckDetail] = field(default_factory=list)
    broken_violations: List[CheckDetail] = field(default_factory=list)
    passed_must_deny: List[CheckDetail] = field(default_factory=list)
    passed_must_allow: List[CheckDetail] = field(default_factory=list)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "verdict": self.verdict.value,
            "is_safe": self.is_safe,
            "is_intact": self.is_intact,
            "counts": {
                "unsafe_violations": len(self.unsafe_violations),
                "broken_violations": len(self.broken_violations),
                "passed_must_deny": len(self.passed_must_deny),
                "passed_must_allow": len(self.passed_must_allow),
            },
            "unsafe_violations": [v.to_dict() for v in self.unsafe_violations],
            "broken_violations": [v.to_dict() for v in self.broken_violations],
            "error_message": self.error_message,
            "metadata": self.metadata,
        }

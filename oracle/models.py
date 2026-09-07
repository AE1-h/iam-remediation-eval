"""
Data structures representing IAM policy statements, requests, and test cases.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class Statement:
    sid: str
    effect: str  # "Allow" or "Deny"
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IAMPolicy:
    version: Optional[str]
    statements: List[Statement]
    raw_dict: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionCheck:
    action: str
    resource: str
    description: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestCase:
    case_id: str
    title: str
    cloud: str  # "aws" or "gcp"
    initial_policy: Dict[str, Any]
    must_deny: List[PermissionCheck]
    must_allow: List[PermissionCheck]
    notes: str = ""
    directory: Optional[Path] = None

    @classmethod
    def load_from_dir(cls, directory: Union[str, Path]) -> "TestCase":
        path = Path(directory)
        case_id = path.name

        with open(path / "policy.json", "r", encoding="utf-8") as f:
            policy_data = json.load(f)

        with open(path / "must_deny.json", "r", encoding="utf-8") as f:
            deny_data = json.load(f)

        with open(path / "must_allow.json", "r", encoding="utf-8") as f:
            allow_data = json.load(f)

        notes = ""
        notes_file = path / "NOTES.md"
        if notes_file.exists():
            with open(notes_file, "r", encoding="utf-8") as f:
                notes = f.read()

        cloud = "gcp" if "bindings" in policy_data or "roles/" in str(policy_data) else "aws"
        title = case_id

        def parse_checks(raw_list: List[Dict[str, Any]]) -> List[PermissionCheck]:
            checks = []
            for item in raw_list:
                checks.append(
                    PermissionCheck(
                        action=item.get("action", item.get("permission", "")),
                        resource=item.get("resource", "*"),
                        description=item.get("description", ""),
                        context=item.get("context", {}),
                    )
                )
            return checks

        return cls(
            case_id=case_id,
            title=title,
            cloud=cloud,
            initial_policy=policy_data,
            must_deny=parse_checks(deny_data),
            must_allow=parse_checks(allow_data),
            notes=notes,
            directory=path,
        )

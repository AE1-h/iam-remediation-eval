"""GCP role -> permission data, loaded from oracle/data/gcp_roles.json.

Kept in its own module so the evaluator can import it by name. The mutation
harness execs the evaluator's source in a namespace without __file__, so path
resolution must not live there.

Predefined roles carry the permission list exactly as published on Google's
roles-and-permissions reference (retrieved 2026-09-08). The basic roles
owner/editor/viewer grant thousands of permissions across every service and are
not enumerable here; they remain approximations and are flagged verified=false.
GCP_ROLE_META preserves that provenance so a caller can tell the two apart.

A role absent from this data is reported INVALID by the oracle. That means
unmodelled, not non-existent.
"""
import json
from pathlib import Path
from typing import Any, Dict, List

DATA_PATH = Path(__file__).resolve().parent / "data" / "gcp_roles.json"

with open(DATA_PATH, encoding="utf-8") as _fh:
    _DOC = json.load(_fh)

GCP_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    role: entry["permissions"] for role, entry in _DOC["roles"].items()
}
GCP_ROLE_META: Dict[str, Dict[str, Any]] = {
    role: {k: v for k, v in entry.items() if k != "permissions"}
    for role, entry in _DOC["roles"].items()
}
GCP_ROLE_DATA_META: Dict[str, Any] = _DOC["_meta"]

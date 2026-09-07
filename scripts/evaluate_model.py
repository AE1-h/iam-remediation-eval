#!/usr/bin/env python3
"""Record a real model command's outputs and deterministic grades, separately from fixtures."""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase
from runner.external_model import build_request, request_digest, invoke


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True, help="Exact model/version sent to provider; caller-declared")
    parser.add_argument("--config", required=True, help="JSON object documenting generation parameters")
    parser.add_argument("--output", required=True, type=Path, help="New run directory (must not already exist)")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args()
    if not args.command or args.timeout <= 0:
        parser.error("A command and positive timeout are required")
    try:
        config = json.loads(args.config)
    except ValueError:
        parser.error("--config must be a JSON object")
    if not isinstance(config, dict):
        parser.error("--config must be a JSON object")
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [TestCase.load_from_dir(p) for p in sorted((REPO_ROOT / "cases").iterdir()) if p.is_dir()]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO_ROOT, text=True).strip())
    hashes = {str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for folder in ("oracle", "runner", "cases", "scripts") for p in sorted((REPO_ROOT / folder).rglob("*"))
              if p.is_file() and p.suffix in {".py", ".json", ".md"}}
    metadata = {"evaluation_kind": "external_command", "provider": args.provider, "model": args.model,
                "model_identity_source": "caller_declared", "generation_config": config,
                "command": args.command, "revision": revision, "dirty_worktree": dirty,
                "input_file_sha256": hashes, "started_at": datetime.now(timezone.utc).isoformat(),
                "workload_checks_disclosed": True, "reference_policy_in_prompt": False,
                "must_deny_in_prompt": False, "case_count": len(cases), "status": "running"}
    metadata["timeout_seconds"] = args.timeout
    metadata_path = args.output / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    failed = 0
    with (args.output / "records.jsonl").open("w") as records:
        for case in cases:
            request = build_request(case)
            record = {"case_id": case.case_id, "request": request, "request_sha256": request_digest(request)}
            try:
                raw = invoke(args.command, request, args.timeout)
                record.update(raw_output=raw, evaluation=DeterministicOracle().evaluate(raw, case).to_dict())
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                failed += 1
                record["execution_error"] = type(exc).__name__
                # Transport errors are not policy INVALID scores.
            records.write(json.dumps(record) + "\n")
            records.flush()
    metadata.update(status="incomplete" if failed else "complete", execution_failures=failed,
                    finished_at=datetime.now(timezone.utc).isoformat())
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Recorded {len(cases)} cases in {args.output}; execution failures: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

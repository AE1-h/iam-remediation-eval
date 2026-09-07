import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oracle.models import TestCase
from runner.external_model import build_request, invoke, request_digest
from runner.evaluate_batch import run_all_benchmarks

ROOT = Path(__file__).resolve().parent.parent


CASE_COUNT = len([p for p in (pathlib.Path(__file__).resolve().parent.parent / "cases").iterdir() if p.is_dir()])


class RunnerTests(unittest.TestCase):
    def test_prompt_excludes_answer_key_notes_and_attack_checks(self):
        case = TestCase.load_from_dir(ROOT / "cases" / "01-passrole-runinstances")
        request = build_request(case)
        other = copy.deepcopy(case)
        other.notes = "ANSWER_KEY_SENTINEL"
        other.must_deny = []
        other.directory = Path("/does-not-exist")
        self.assertEqual(request, build_request(other))
        self.assertEqual(request_digest(request), request_digest(build_request(other)))
        self.assertNotIn("ANSWER_KEY_SENTINEL", json.dumps(request))

    def test_adapter_preserves_stdout(self):
        command = [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"]
        request = {"messages": []}
        self.assertEqual(invoke(command, request, 5), json.dumps(request))

    def test_adapter_failure_is_not_policy_output(self):
        with self.assertRaises(RuntimeError):
            invoke([sys.executable, "-c", "raise SystemExit(2)"], {}, 5)

    def test_adapter_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            invoke([sys.executable, "-c", "import time; time.sleep(5)"], {}, 0.05)

    def test_fixture_provenance_and_matrix(self):
        report = run_all_benchmarks(ROOT)
        self.assertEqual(report["metadata"]["llm_calls"], 0)
        for data in report["agents"].values():
            self.assertEqual(sum(data["matrix_counts"].values()), CASE_COUNT)
            for result in data["per_case"]:
                self.assertIn("proposed_policy", result["metadata"])

    def test_model_cli_records_raw_outputs_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            command = [sys.executable, str(ROOT / "scripts" / "evaluate_model.py"),
                       "--provider", "test-only", "--model", "no-model-called", "--config", "{}",
                       "--output", str(output), "--command", sys.executable, "-c", "print('{}')"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            records = (output / "records.jsonl").read_text()
            self.assertEqual(len(records.splitlines()), CASE_COUNT)
            self.assertEqual(json.loads(records.splitlines()[0])["raw_output"], "{}\n")
            metadata = json.loads((output / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "complete")
            self.assertFalse(metadata["reference_policy_in_prompt"])
            again = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((output / "records.jsonl").read_text(), records)

    def test_model_cli_transport_failures_are_ungraded(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            command = [sys.executable, str(ROOT / "scripts" / "evaluate_model.py"),
                       "--provider", "test-only", "--model", "no-model-called", "--config", "{}",
                       "--output", str(output), "--command", sys.executable, "-c", "raise SystemExit(3)"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            metadata = json.loads((output / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "incomplete")
            self.assertEqual(metadata["execution_failures"], CASE_COUNT)
            for line in (output / "records.jsonl").read_text().splitlines():
                self.assertNotIn("evaluation", json.loads(line))

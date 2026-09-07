"""The audit must detect drift, not just inspect selected saved rates."""
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import validate_repo

ROOT = Path(__file__).resolve().parent.parent


class ValidationTests(unittest.TestCase):
    def test_artifact_drift_fails_without_rewriting(self):
        for relative in ("self_test_eval.json", "raw/reference_policy_check.json", "report.md"):
            with self.subTest(artifact=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                shutil.copytree(ROOT / "cases", root / "cases")
                shutil.copytree(ROOT / "results", root / "results")
                artifact = root / "results" / relative
                if relative.endswith(".json"):
                    data = json.loads(artifact.read_text())
                    if isinstance(data, list):
                        data[0]["is_intact"] = False
                    else:
                        data["agents"]["reference_policy_check"]["per_case"][0]["is_intact"] = False
                    corrupted = json.dumps(data)
                else:
                    corrupted = artifact.read_text() + "Unverified claim.\n"
                artifact.write_text(corrupted)
                with patch.object(validate_repo, "REPO_ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        validate_repo.main()
                self.assertEqual(raised.exception.code, 1)
                self.assertEqual(artifact.read_text(), corrupted)

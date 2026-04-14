from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.generate_synthetic_corpus import DEFAULT_SPEC_PATH, generate_corpus
from scripts.validate_synthetic_corpus import validate_corpus


class SyntheticCorpusScaffoldTests(unittest.TestCase):
    def test_generator_and_validator_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            corpus_root = Path(temp_dir) / "synthetic-corpus"
            manifest = generate_corpus(DEFAULT_SPEC_PATH, corpus_root)

            self.assertEqual(manifest["sample_count"], 12)
            self.assertTrue((corpus_root / "manifest.json").exists())

            errors = validate_corpus(corpus_root)
            self.assertEqual(errors, [])

            manifest_payload = json.loads((corpus_root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest_payload["sample_count"], 12)
            self.assertEqual(len(manifest_payload["samples"]), 12)


if __name__ == "__main__":
    unittest.main()

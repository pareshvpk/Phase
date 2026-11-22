import io
import hashlib
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import evaluate


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "monitor.jsonl"
        self.labels = Path(self.temp.name) / "labels.csv"

    def write_flows(self, predictions, observed=()):
        rows = [dict(type="flow", experimental_model_class=label,
                     observations=[dict(kind="destination_port_fanout")] if i in observed else [])
                for i, label in enumerate(predictions, 1)]
        rows.append(dict(type="summary", flows=len(predictions), frames=len(predictions), skipped_frames=0))
        self.path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    def test_model_and_pattern_metrics_are_separate(self):
        self.write_flows(["normal", "dos", "normal", "probe"], observed=(3, 4))
        report = evaluate.evaluate(self.path, {1: "normal", 2: "normal", 3: "probe", 4: "probe"})
        model = report["experimental_model"]
        self.assertEqual(.5, model["accuracy"])
        self.assertEqual(.5, model["binary"]["recall"])
        self.assertEqual(.5, model["binary"]["false_positive_rate"])
        self.assertEqual(1, report["traffic_observations"]["recall"])
        self.assertEqual(0, report["traffic_observations"]["false_positive_rate"])
        self.assertEqual(2, model["per_class"]["probe"]["support"])

    def test_missing_class_metrics_are_null_not_perfect(self):
        self.write_flows(["normal"])
        report = evaluate.evaluate(self.path, {1: "normal"})
        self.assertIsNone(report["experimental_model"]["binary"]["recall"])
        self.assertIsNone(report["experimental_model"]["per_class"]["probe"]["recall"])
        json.dumps(report, allow_nan=False)

    def test_partial_labels_require_explicit_opt_in(self):
        self.write_flows(["normal", "probe"])
        with self.assertRaisesRegex(ValueError, "every flow"):
            evaluate.evaluate(self.path, {1: "normal"})
        report = evaluate.evaluate(self.path, {1: "normal"}, allow_partial=True)
        self.assertEqual(.5, report["label_coverage"])
        self.assertTrue(report["partial"])
        self.assertEqual(1, report["labelled_flows"])

    def test_out_of_range_labels_are_rejected_even_in_partial_mode(self):
        self.write_flows(["normal"])
        with self.assertRaisesRegex(ValueError, "absent"):
            evaluate.evaluate(self.path, {1: "normal", 2: "dos"}, True)

    def test_label_csv_rejects_duplicates_unknown_labels_and_bad_indexes(self):
        for body in ("1,normal\n1,dos", "1,unknown", "0,normal", "x,dos", "1,dos,extra", "1"):
            with self.subTest(body=body):
                self.labels.write_text("flow_index,label\n" + body, encoding="utf-8")
                with self.assertRaises(ValueError):
                    evaluate.load_labels(self.labels)
        self.labels.write_text("flow_index,label\n1,probe\n", encoding="utf-8-sig")
        self.assertEqual({1: "probe"}, evaluate.load_labels(self.labels))

    def test_incomplete_or_inconsistent_output_is_rejected(self):
        self.write_flows(["normal"])
        complete = self.path.read_text(encoding="utf-8")
        invalid = [complete.splitlines()[0], complete.replace('"flows": 1', '"flows": 2'),
                   complete + "\n" + complete, '[]', '{bad json}',
                   complete.replace('"frames": 1', '"frames": true'),
                   complete.replace('"skipped_frames": 0', '"skipped_frames": 3'),
                   complete.replace('"skipped_frames": 0', '"skipped_frames": 1'),
                   complete.replace('"normal"', '"unknown"'),
                   complete.replace('"observations": []', '"observations": [null]')]
        for text in invalid:
            with self.subTest(text=text):
                self.path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    evaluate.evaluate(self.path, {1: "normal"})

    def test_cli_outputs_hashes_and_machine_readable_metrics(self):
        self.write_flows(["probe"], observed=(1,))
        self.labels.write_text("flow_index,label\n1,probe\n", encoding="utf-8")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, evaluate.main(["--input", str(self.path), "--labels", str(self.labels)]))
        result = json.loads(output.getvalue())
        self.assertEqual(64, len(result["monitor_sha256"]))
        self.assertEqual(64, len(result["labels_sha256"]))
        self.assertEqual(1, result["experimental_model"]["accuracy"])

    def test_cli_failure_does_not_emit_a_success_report(self):
        self.write_flows(["normal"])
        self.labels.write_text("wrong,header\n", encoding="utf-8")
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(1, evaluate.main(["--input", str(self.path), "--labels", str(self.labels)]))
        self.assertEqual("", output.getvalue())
        self.assertIn("header", errors.getvalue())

    def test_label_hash_identifies_the_bytes_actually_used(self):
        self.write_flows(["normal"])
        original = b"flow_index,label\n1,normal\n"
        self.labels.write_bytes(original)
        real_evaluate = evaluate.evaluate

        def replace_labels(*args):
            self.labels.write_bytes(b"flow_index,label\n1,probe\n")
            return real_evaluate(*args)

        output = io.StringIO()
        with patch.object(evaluate, "evaluate", side_effect=replace_labels), redirect_stdout(output):
            self.assertEqual(0, evaluate.main(["--input", str(self.path), "--labels", str(self.labels)]))
        result = json.loads(output.getvalue())
        self.assertEqual(hashlib.sha256(original).hexdigest(), result["labels_sha256"])
        self.assertEqual(1, result["experimental_model"]["accuracy"])


if __name__ == "__main__":
    unittest.main()

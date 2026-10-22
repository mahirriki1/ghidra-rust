"""Differential-benchmark comparator regressions using small synthetic documents."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "compare_ghidra_benchmark", SCRIPTS / "compare-ghidra-benchmark.py"
)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def truth_document():
    # Two authored functions, a runtime function, a PLT stub and an alias-free
    # zero-size authored entry that can be recalled but bounds no interval.
    return {
        "schema_version": 1,
        "document_type": "ground_truth",
        "functions": [
            {"rva": "0x1000", "size": 0x20, "scope": "primary", "names": ["main"]},
            {"rva": "0x1020", "size": 0x10, "scope": "primary", "names": ["bench_a"]},
            {"rva": "0x1040", "size": 0, "scope": "primary", "names": ["bench_z"]},
            {"rva": "0x1100", "size": 0x10, "scope": "runtime", "names": ["_start"]},
        ],
        "plt_sections": [{"name": ".plt", "rva": "0x900", "size": 0x40, "file_offset": 0x900}],
        "executable_sections": [
            {"name": ".text", "rva": "0x1000", "size": 0x200, "file_offset": 0x1000},
        ],
        "calls": [
            {"from_rva": "0x1004", "target_rva": "0x1020"},
            {"from_rva": "0x1008", "target_rva": "0x910"},
        ],
    }


def export(tool, functions, calls=(), decompilations=(), tool_base="0x0", status="ok"):
    return {
        "schema_version": 1,
        "document_type": "tool_export",
        "run_id": f"case-r1-{tool}",
        "case_id": "case",
        "tool": tool,
        "status": status,
        "input": {"sha256": "ab" * 32},
        "addressing": {"load_base": "0x0", "original_base": "0x0", "tool_base": tool_base},
        "executable_blocks": [],
        "functions": [
            {"rva": hex(rva), "raw": hex(rva + int(tool_base, 16))} for rva in functions
        ],
        "calls": [
            {
                "kind": kind,
                "from_rva": hex(source),
                "target_rva": hex(target),
                "raw_from": hex(source + int(tool_base, 16)),
            }
            for kind, source, target in calls
        ],
        "decompilations": list(decompilations),
    }


class DocumentTests(unittest.TestCase):
    def test_rejects_duplicate_keys_nonfinite_numbers_and_nesting(self):
        with self.assertRaises(compare.InvalidDocument):
            compare.parse_document(b'{"schema_version": 1, "schema_version": 1}')
        with self.assertRaises(compare.InvalidDocument):
            compare.parse_document(b'{"schema_version": 1, "x": NaN}')
        nested = b'{"schema_version": 1, "x": ' + b"[" * 20 + b"]" * 20 + b"}"
        with self.assertRaises(compare.InvalidDocument):
            compare.parse_document(nested)
        with self.assertRaises(compare.InvalidDocument):
            compare.parse_document(b'{"schema_version": 1, "x": "\xff"}')

    def test_addresses_must_be_canonical_lowercase_hex(self):
        self.assertEqual(compare.address("0x1f"), 0x1F)
        for invalid in ("1f", "0x1F", "0x", "0x" + "1" * 17, 31):
            with self.assertRaises(compare.InvalidDocument):
                compare.address(invalid)

    def test_rebased_raw_addresses_must_match_rvas(self):
        rebased = export("ghidra", [0x1000], tool_base="0x100000")
        rebased["addressing"]["original_base"] = "0x0"
        compare.validate_export(rebased, {})
        rebased["functions"][0]["raw"] = "0x1000"
        with self.assertRaises(compare.InvalidDocument):
            compare.validate_export(rebased, {})

    def test_identity_mismatch_is_rejected(self):
        document = export("ghidra", [0x1000])
        with self.assertRaises(compare.InvalidDocument):
            compare.validate_export(document, {"sha256": "cd" * 32})
        with self.assertRaises(compare.InvalidDocument):
            compare.validate_export(document, {"tool": "ghidra-rust"})

    def test_suite_paths_cannot_escape(self):
        with self.assertRaises(compare.InvalidDocument):
            compare.resolve(Path("/suite"), "../elsewhere.json")
        with self.assertRaises(compare.InvalidDocument):
            compare.resolve(Path("/suite"), "/etc/passwd")


class MetricTests(unittest.TestCase):
    def setUp(self):
        self.truth = compare.Truth(truth_document())

    def test_function_scope_precision_and_recall(self):
        # 0x1028 lies inside bench_a's extent but is no entry (false positive);
        # 0x2000 is outside every authored extent and is not scored as one.
        # The zero-size bench_z entry counts toward recall only.
        metrics = compare.function_metrics({0x1000, 0x1028, 0x1040, 0x1100, 0x2000}, self.truth)
        primary = metrics["primary"]
        self.assertEqual(
            (primary["true_positive"], primary["false_positive"], primary["false_negative"]),
            (2, 1, 1),
        )
        self.assertEqual(primary["precision"], 0.5)
        self.assertEqual(primary["recall"], 2 / 3)
        self.assertEqual(primary["missed"], ["0x1020"])
        self.assertEqual(primary["extra"], ["0x1028"])
        self.assertEqual(metrics["runtime_recall"], 1.0)
        self.assertEqual(metrics["outside_symbols"], 2)

    def test_zero_denominators_are_null(self):
        empty = compare.Truth({**truth_document(), "functions": [], "calls": []})
        primary = compare.function_metrics(set(), empty)["primary"]
        self.assertIsNone(primary["precision"])
        self.assertIsNone(primary["recall"])

    def test_calls_score_literal_calls_and_report_flow_overrides(self):
        document = export(
            "ghidra",
            [0x1000],
            calls=[
                ("call", 0x1004, 0x1020),
                ("call", 0x1008, 0x910),
                ("flow_override", 0x1024, 0x1000),
                ("call", 0x2000, 0x1000),
            ],
        )
        metrics = compare.call_metrics(document, self.truth)
        self.assertEqual(metrics["flow_overrides"], 1)
        self.assertEqual(metrics["all"]["precision"], 1.0)
        self.assertEqual(metrics["all"]["recall"], 1.0)
        self.assertEqual(metrics["plt_target"]["true_positive"], 1)
        self.assertEqual(metrics["internal_target"]["true_positive"], 1)

    def test_missing_requested_functions_remain_in_the_denominator(self):
        records = [
            {"rva": "0x1000", "status": "success", "c": "int main(void){}"},
            {"rva": "0x1020", "status": "not_discovered", "c": None},
            {"rva": "0x1040", "status": "timeout", "c": None},
        ]
        metrics = compare.decompile_metrics(export("ghidra-rust", [], decompilations=records))
        self.assertEqual(metrics["requested"], 3)
        self.assertEqual(metrics["counts"]["not_discovered"], 1)
        self.assertEqual(metrics["success_given_discovered"], 0.5)

    def test_failed_exports_report_no_quality(self):
        metrics = compare.export_metrics(export("ghidra", [], status="failed"), self.truth)
        self.assertNotIn("functions", metrics)


class SimilarityTests(unittest.TestCase):
    def test_normalization_ignores_comments_layout_and_identifier_names(self):
        a = compare.normalize("int f(int a) { /* x */ return a + 1; }")
        b = compare.normalize("int g(int param_1)\n{\n  return param_1 + 1; // y\n}")
        self.assertEqual(a, b)

    def test_strings_and_constants_are_preserved(self):
        a = compare.normalize('puts("/* not a comment */"); return 1;')
        b = compare.normalize('puts("other"); return 2;')
        self.assertIn('"/* not a comment */"', a)
        self.assertNotEqual(a, b)
        self.assertLess(compare.trigram_dice(a, b), 1.0)

    def test_similarity_skips_truncated_or_unmatched_output(self):
        rust = export("ghidra-rust", [], decompilations=[
            {"rva": "0x1000", "status": "success", "c": "int f(void){return 0;}"},
            {"rva": "0x1020", "status": "success", "c": "x", "export_truncation": True},
            {"rva": "0x1040", "status": "error", "c": None},
        ])
        ghidra = export("ghidra", [], decompilations=[
            {"rva": "0x1000", "status": "success", "c": "int g(void){return 0;}"},
            {"rva": "0x1020", "status": "success", "c": "x"},
            {"rva": "0x1040", "status": "success", "c": "y"},
        ])
        result = compare.similarity(rust, ghidra)
        self.assertEqual((result["compared"], result["normalized_exact"]), (1, 1))
        self.assertEqual(result["similarity_skipped"], 1)

    def test_token_budget_skips_oversized_output(self):
        self.assertIsNone(compare.normalize("x;" * (compare.MAX_TOKENS + 1)))


class SuiteTests(unittest.TestCase):
    def test_suite_keeps_failures_and_invalid_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "truth.json").write_text(json.dumps(truth_document()))
            good = export("ghidra-rust", [0x1000, 0x1020])
            (root / "rust.json").write_text(json.dumps(good))
            (root / "ghidra.json").write_text('{"schema_version": 1, "schema_version": 1}')
            run = {"case_id": "case", "repetition": 1, "status": "ok", "wall_ms": 5.0,
                   "export_present": True, "memory": {}}
            suite = {
                "schema_version": 1,
                "document_type": "suite",
                "cases": [{"case_id": "case", "sha256": "ab" * 32, "truth": "truth.json"}],
                "runs": [
                    {**run, "run_id": "case-r1-ghidra-rust", "tool": "ghidra-rust",
                     "export": "rust.json"},
                    {**run, "run_id": "case-r1-ghidra", "tool": "ghidra", "export": "ghidra.json"},
                    {**run, "run_id": "case-r2-ghidra", "tool": "ghidra", "repetition": 2,
                     "status": "timeout", "export_present": False, "export": "missing.json"},
                ],
            }
            (root / "suite.json").write_text(json.dumps(suite))
            report = compare.compare_suite(root / "suite.json")
            statuses = [run["status"] for run in report["runs"]]
            self.assertEqual(statuses, ["ok", "invalid_export", "timeout"])
            self.assertEqual(report["runs"][0]["metrics"]["functions"]["primary"]["recall"], 2 / 3)
            ghidra = next(g for g in report["summary"] if g["tool"] == "ghidra")
            self.assertEqual((ghidra["runs"], ghidra["failures"]), (2, 2))
            self.assertIn("Cost", compare.table(report))


if __name__ == "__main__":
    unittest.main()

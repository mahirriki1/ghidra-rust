#!/usr/bin/env python3
"""Compare ghidra-rust and Ghidra differential-benchmark exports.

Reads a suite manifest written by tests/ghidra_differential.rs (or a single
export pair) and prints quality and cost metrics as JSON or a text table. It
only reads its inputs and writes to stdout/stderr. Exports are untrusted data:
sizes, nesting, duplicate keys, addresses and identities are validated.
Run with: python3 -I scripts/compare-ghidra-benchmark.py --suite SUITE.json
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

SCHEMA_VERSION = 1
MAX_DOCUMENT_BYTES = 96 * 1024 * 1024
MAX_DEPTH = 16
MAX_ITEMS = 262_144
MAX_TOKENS = 65_536
MAX_LISTED = 64
ADDRESS = re.compile(r"0x[0-9a-f]{1,16}\Z")
DECOMPILE_STATUSES = (
    "success",
    "not_discovered",
    "timeout",
    "error",
    "cancelled",
    "output_truncated",
    "not_attempted_after_failure",
)


class InvalidDocument(ValueError):
    pass


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidDocument(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name):
    raise InvalidDocument(f"non-finite number {name}")


def _check_depth(value, depth=0):
    if depth > MAX_DEPTH:
        raise InvalidDocument("JSON nesting exceeds its limit")
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise InvalidDocument("JSON array exceeds its item limit")
        children = value
    else:
        return
    for child in children:
        _check_depth(child, depth + 1)


def parse_document(data: bytes):
    if len(data) > MAX_DOCUMENT_BYTES:
        raise InvalidDocument("document exceeds its size limit")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise InvalidDocument(f"malformed JSON: {error}") from None
    _check_depth(value)
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise InvalidDocument("unsupported schema version")
    return value


def load(path: Path, document_type: str):
    with open(path, "rb") as file:
        data = file.read(MAX_DOCUMENT_BYTES + 1)
    value = parse_document(data)
    if value.get("document_type") != document_type:
        raise InvalidDocument(f"{path.name} is not a {document_type} document")
    return value


def address(text) -> int:
    if not isinstance(text, str) or not ADDRESS.match(text):
        raise InvalidDocument(f"invalid address {text!r}")
    return int(text, 16)


def ratio(numerator: int, denominator: int):
    return None if denominator == 0 else numerator / denominator


def listed(values) -> list[str]:
    return [hex(value) for value in sorted(values)[:MAX_LISTED]]


# ---------------------------------------------------------------------------
# Ground truth


class Truth:
    def __init__(self, document):
        self.functions = {}
        self.primary_intervals = []
        for record in document["functions"]:
            rva = address(record["rva"])
            size = record["size"]
            if not isinstance(size, int) or size < 0:
                raise InvalidDocument("invalid truth function size")
            if rva in self.functions:
                raise InvalidDocument("duplicate truth function entry")
            self.functions[rva] = record
            if record["scope"] == "primary" and size > 0:
                self.primary_intervals.append((rva, rva + size))
        self.primary_intervals.sort()
        for (_, end), (start, _) in zip(self.primary_intervals, self.primary_intervals[1:]):
            if start < end:
                raise InvalidDocument("overlapping primary truth extents")
        self.primary = {rva for rva, r in self.functions.items() if r["scope"] == "primary"}
        self.runtime = {rva for rva, r in self.functions.items() if r["scope"] == "runtime"}
        self.plt = [
            (address(s["rva"]), address(s["rva"]) + s["size"]) for s in document["plt_sections"]
        ]
        self.sections = {s["name"]: s for s in document["executable_sections"]}
        self.calls = {
            (address(c["from_rva"]), address(c["target_rva"])) for c in document["calls"]
        }

    def in_primary(self, rva: int) -> bool:
        return any(start <= rva < end for start, end in self.primary_intervals)

    def in_plt(self, rva: int) -> bool:
        return any(start <= rva < end for start, end in self.plt)


# ---------------------------------------------------------------------------
# Tool exports


def validate_export(export, expected: dict):
    for key in ("run_id", "case_id", "tool"):
        if key in expected and export.get(key) != expected[key]:
            raise InvalidDocument(f"export {key} does not match its run")
    if "sha256" in expected and export.get("input", {}).get("sha256") != expected["sha256"]:
        raise InvalidDocument("export input hash does not match its case")
    if export.get("status") not in ("ok", "partial", "failed"):
        raise InvalidDocument("invalid export status")
    if export["status"] == "failed":
        return
    addressing = export["addressing"]
    load_base = address(addressing["load_base"])
    delta = address(addressing["tool_base"]) - address(addressing["original_base"])
    seen = set()
    for function in export["functions"]:
        rva = address(function["rva"])
        if rva in seen:
            raise InvalidDocument("duplicate exported function entry")
        seen.add(rva)
        if address(function["raw"]) - delta - load_base != rva:
            raise InvalidDocument("function RVA is inconsistent with its raw address")
    for call in export["calls"]:
        if call.get("kind", "call") not in ("call", "flow_override"):
            raise InvalidDocument("invalid call kind")
        address(call["from_rva"])
        address(call["target_rva"])
        if address(call["raw_from"]) - delta - load_base != address(call["from_rva"]):
            raise InvalidDocument("call RVA is inconsistent with its raw address")
    for record in export["decompilations"]:
        address(record["rva"])
        if record["status"] not in DECOMPILE_STATUSES:
            raise InvalidDocument("invalid decompilation status")


def section_check(export, truth: Truth):
    """Executable blocks a tool reports must sit where the ELF placed them."""
    matched, mismatched = 0, []
    for block in export.get("executable_blocks") or []:
        section = truth.sections.get(block["name"])
        if section is None:
            continue
        if (
            address(block["rva"]) == address(section["rva"])
            and block.get("file_offset") == section["file_offset"]
        ):
            matched += 1
        else:
            mismatched.append(block["name"])
    return {"matched": matched, "mismatched": mismatched[:MAX_LISTED]}


def function_metrics(entries: set[int], truth: Truth):
    # Recall uses exact authored entries, including zero-size symbols. Only
    # nonzero authored extents bound precision: an entry elsewhere is not
    # proven false merely because the corpus symbols do not describe it.
    found = len(entries & truth.primary)
    scoped = {rva for rva in entries if truth.in_primary(rva)}
    scoped_hits = len(scoped & truth.primary)
    fp = len(scoped - truth.primary)
    everything = set(truth.functions)
    return {
        "primary": {
            "true_positive": found,
            "false_positive": fp,
            "false_negative": len(truth.primary - entries),
            "precision": ratio(scoped_hits, scoped_hits + fp),
            "recall": ratio(found, len(truth.primary)),
            "missed": listed(truth.primary - entries),
            "extra": listed(scoped - truth.primary),
        },
        "runtime_recall": ratio(len(truth.runtime & entries), len(truth.runtime)),
        "whole_image_symbol_recall": ratio(len(everything & entries), len(everything)),
        "outside_symbols": len(entries - everything),
    }


def call_metrics(export, truth: Truth):
    # Truth is literal call instructions; analysis-overridden jumps (tail and
    # PLT jumps that a tool treats as calls) are reported, not scored.
    predicted = {
        (address(c["from_rva"]), address(c["target_rva"]))
        for c in export["calls"]
        if c.get("kind", "call") == "call" and truth.in_primary(address(c["from_rva"]))
    }
    result = {
        "flow_overrides": sum(1 for c in export["calls"] if c.get("kind", "call") != "call"),
    }
    strata = {
        "all": lambda target: True,
        "plt_target": truth.in_plt,
        "internal_target": lambda target: not truth.in_plt(target),
    }
    for name, keep in strata.items():
        expected = {pair for pair in truth.calls if keep(pair[1])}
        actual = {pair for pair in predicted if keep(pair[1])}
        tp = len(expected & actual)
        result[name] = {
            "true_positive": tp,
            "false_positive": len(actual - expected),
            "false_negative": len(expected - actual),
            "precision": ratio(tp, len(actual)),
            "recall": ratio(tp, len(expected)),
        }
    return result


def decompile_metrics(export):
    counts = Counter(record["status"] for record in export["decompilations"])
    discovered = sum(
        count
        for status, count in counts.items()
        if status not in ("not_discovered", "not_attempted_after_failure")
    )
    return {
        "requested": len(export["decompilations"]),
        "counts": {status: counts.get(status, 0) for status in DECOMPILE_STATUSES},
        "success_given_discovered": ratio(counts.get("success", 0), discovered),
        "export_truncated": sum(1 for r in export["decompilations"] if r.get("export_truncation")),
    }


def export_metrics(export, truth: Truth | None):
    metrics = {
        "status": export["status"],
        "failure_stage": export.get("failure_stage"),
        "error": export.get("error"),
    }
    if export["status"] == "failed":
        return metrics
    entries = {address(f["rva"]) for f in export["functions"]}
    metrics["functions_exported"] = len(entries)
    metrics["coverage"] = export.get("coverage")
    metrics["decompilation"] = decompile_metrics(export)
    metrics["timings"] = export.get("timings")
    if truth is not None:
        metrics["functions"] = function_metrics(entries, truth)
        metrics["calls"] = call_metrics(export, truth)
        metrics["sections"] = section_check(export, truth)
    return metrics


# ---------------------------------------------------------------------------
# Pseudocode text similarity (diagnostic only; not semantic equivalence)

C_KEYWORDS = frozenset(
    "auto break case char const continue default do double else enum extern float for "
    "goto if inline int long register restrict return short signed sizeof static struct "
    "switch typedef union unsigned void volatile while bool true false NULL".split()
)
TOKEN = re.compile(
    r"""(?P<comment>/\*.*?\*/|//[^\n]*)
      |(?P<string>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
      |(?P<ident>[A-Za-z_][A-Za-z0-9_]*)
      |(?P<number>0[xX][0-9a-fA-F]+[uUlL]*|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?[uUlLfF]*)
      |(?P<space>\s+)
      |(?P<op>->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^~!<>=?:;,.(){}\[\]#])
      |(?P<other>.)""",
    re.S | re.X,
)


def normalize(text: str):
    tokens, names = [], {}
    for match in TOKEN.finditer(text):
        kind = match.lastgroup
        if kind in ("comment", "space"):
            continue
        value = match.group()
        if kind == "ident" and value not in C_KEYWORDS:
            value = names.setdefault(value, f"id{len(names)}")
        tokens.append(value)
        if len(tokens) > MAX_TOKENS:
            return None
    return tokens


def trigram_dice(a, b):
    grams_a = Counter(zip(a, a[1:], a[2:]))
    grams_b = Counter(zip(b, b[1:], b[2:]))
    total = sum(grams_a.values()) + sum(grams_b.values())
    if total == 0:
        return 1.0 if a == b else 0.0
    shared = sum((grams_a & grams_b).values())
    return 2 * shared / total


def similarity(rust, ghidra):
    by_rva = {r["rva"]: r for r in ghidra["decompilations"]}
    scores, exact, skipped = [], 0, 0
    for record in rust["decompilations"]:
        other = by_rva.get(record["rva"])
        if not other or record["status"] != "success" or other["status"] != "success":
            continue
        if record.get("export_truncation") or other.get("export_truncation"):
            skipped += 1
            continue
        a, b = normalize(record["c"] or ""), normalize(other["c"] or "")
        if a is None or b is None:
            skipped += 1
            continue
        exact += a == b
        scores.append(trigram_dice(a, b))
    return {
        "compared": len(scores),
        "normalized_exact": exact,
        "median_trigram_dice": statistics.median(scores) if scores else None,
        "min_trigram_dice": min(scores) if scores else None,
        "similarity_skipped": skipped,
        "note": "diagnostic text similarity, not semantic equivalence",
    }


def overlap(rust, ghidra, truth: Truth | None):
    a = {address(f["rva"]) for f in rust["functions"]}
    b = {address(f["rva"]) for f in ghidra["functions"]}
    result = {
        "both": len(a & b),
        "rust_only": len(a - b),
        "ghidra_only": len(b - a),
        "rust_only_sample": listed(a - b),
        "ghidra_only_sample": listed(b - a),
    }
    if truth is not None:
        result["primary_missed_by_both"] = listed(truth.primary - a - b)
    return result


# ---------------------------------------------------------------------------
# Suite aggregation


def nearest_rank(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def distribution(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        return None
    return {
        "n": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "p95_nearest_rank": nearest_rank(values, 0.95),
        "max": max(values),
        "values": values,
    }


def resolve(suite_dir: Path, relative) -> Path:
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise InvalidDocument(f"suite path {relative!r} escapes the suite directory")
    return suite_dir / relative


def compare_suite(path: Path):
    suite = load(path, "suite")
    directory = path.parent
    cases = {case["case_id"]: case for case in suite["cases"]}
    truths = {}
    for case_id, case in cases.items():
        if case.get("truth"):
            truths[case_id] = Truth(load(resolve(directory, case["truth"]), "ground_truth"))
    runs, exports = [], {}
    for run in suite["runs"]:
        case = cases.get(run["case_id"])
        if case is None:
            raise InvalidDocument("run names an unknown case")
        record = {key: run.get(key) for key in ("run_id", "case_id", "tool", "repetition", "status")}
        record["wall_ms"] = run.get("wall_ms")
        record["memory"] = run.get("memory")
        export_path = resolve(directory, run["export"])
        if run.get("export_present"):
            try:
                export = load(export_path, "tool_export")
                validate_export(
                    export,
                    {"run_id": run["run_id"], "case_id": run["case_id"], "tool": run["tool"],
                     "sha256": case["sha256"]},
                )
                record["metrics"] = export_metrics(export, truths.get(run["case_id"]))
                exports[(run["case_id"], run["repetition"], run["tool"])] = export
            except (InvalidDocument, KeyError, TypeError) as error:
                record["status"] = "invalid_export"
                record["error"] = str(error)[:4096]
        runs.append(record)
    pairs = []
    for (case_id, repetition, tool), rust in sorted(exports.items()):
        ghidra = exports.get((case_id, repetition, "ghidra"))
        if tool != "ghidra-rust" or ghidra is None:
            continue
        if "failed" in (rust["status"], ghidra["status"]):
            continue
        pairs.append({
            "case_id": case_id,
            "repetition": repetition,
            "overlap": overlap(rust, ghidra, truths.get(case_id)),
            "similarity": similarity(rust, ghidra),
        })
    groups = {}
    for run in runs:
        group = groups.setdefault((run["case_id"], run["tool"]), {"runs": 0, "failures": 0,
                                                                 "wall_ms": [], "rss": [], "pss": []})
        group["runs"] += 1
        if run["status"] != "ok":
            group["failures"] += 1
            continue
        group["wall_ms"].append(run["wall_ms"])
        memory = run.get("memory") or {}
        group["rss"].append(memory.get("observed_peak_sum_rss_kib"))
        group["pss"].append(memory.get("observed_peak_sum_pss_kib"))
    summary = [
        {
            "case_id": case_id,
            "tool": tool,
            "runs": group["runs"],
            "failures": group["failures"],
            "wall_ms": distribution(group["wall_ms"]),
            "observed_peak_sum_rss_kib": distribution(group["rss"]),
            "observed_peak_sum_pss_kib": distribution(group["pss"]),
        }
        for (case_id, tool), group in sorted(groups.items())
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "document_type": "comparison",
        "percentile": "nearest rank",
        "runs": runs,
        "pairs": pairs,
        "summary": summary,
        "limitations": suite.get("limitations", []),
    }


def compare_pair(rust_path: Path, ghidra_path: Path, truth_path: Path | None):
    truth = Truth(load(truth_path, "ground_truth")) if truth_path else None
    rust = load(rust_path, "tool_export")
    ghidra = load(ghidra_path, "tool_export")
    validate_export(rust, {"tool": "ghidra-rust"})
    validate_export(ghidra, {"tool": "ghidra", "sha256": rust["input"]["sha256"]})
    result = {
        "schema_version": SCHEMA_VERSION,
        "document_type": "comparison",
        "rust": export_metrics(rust, truth),
        "ghidra": export_metrics(ghidra, truth),
    }
    if "failed" not in (rust["status"], ghidra["status"]):
        result["overlap"] = overlap(rust, ghidra, truth)
        result["similarity"] = similarity(rust, ghidra)
    return result


# ---------------------------------------------------------------------------
# Text output


def pct(value):
    return "  n/a" if value is None else f"{100 * value:5.1f}"


def table(report) -> str:
    lines = []
    header = (
        f"{'case':<20} {'tool':<11} {'rep':>3} {'status':<14} {'funcs':>6} "
        f"{'fn P%':>6} {'fn R%':>6} {'call P%':>7} {'call R%':>7} "
        f"{'C ok/miss/fail/trunc':>21}"
    )
    lines += ["Quality (primary corpus scope; see docs/analysis-performance.md)", header,
              "-" * len(header)]
    for run in report["runs"]:
        metrics = run.get("metrics") or {}
        functions = (metrics.get("functions") or {}).get("primary") or {}
        calls = (metrics.get("calls") or {}).get("all") or {}
        decompile = (metrics.get("decompilation") or {}).get("counts") or {}
        failures = sum(decompile.get(k, 0) for k in ("timeout", "error", "cancelled",
                                                        "not_attempted_after_failure"))
        c_column = (
            f"{decompile.get('success', 0)}/{decompile.get('not_discovered', 0)}/"
            f"{failures}/{decompile.get('output_truncated', 0)}" if decompile else "-"
        )
        lines.append(
            f"{run['case_id']:<20} {run['tool']:<11} {run['repetition']:>3} "
            f"{run['status']:<14} {metrics.get('functions_exported', '-'):>6} "
            f"{pct(functions.get('precision')):>6} {pct(functions.get('recall')):>6} "
            f"{pct(calls.get('precision')):>7} {pct(calls.get('recall')):>7} {c_column:>21}"
        )
    lines += ["", "Cost (fresh process to exit; observed peak contemporaneous sums)"]
    header = (f"{'case':<20} {'tool':<11} {'ok/runs':>7} {'wall ms min/median/p95/max':>34} "
              f"{'peak RSS MiB':>12} {'peak PSS MiB':>12}")
    lines += [header, "-" * len(header)]
    for group in report["summary"]:
        wall = group["wall_ms"]
        wall_text = (f"{wall['min']:.0f}/{wall['median']:.0f}/{wall['p95_nearest_rank']:.0f}/"
                     f"{wall['max']:.0f}" if wall else "-")
        rss = group["observed_peak_sum_rss_kib"]
        pss = group["observed_peak_sum_pss_kib"]
        lines.append(
            f"{group['case_id']:<20} {group['tool']:<11} "
            f"{group['runs'] - group['failures']:>3}/{group['runs']:<3} {wall_text:>34} "
            f"{(rss['median'] / 1024 if rss else float('nan')):>12.0f} "
            f"{(pss['median'] / 1024 if pss else float('nan')):>12.0f}"
        )
    if report["pairs"]:
        lines += ["", "Cross-tool function overlap and pseudocode text similarity (diagnostic)"]
        header = (f"{'case':<20} {'rep':>3} {'both':>5} {'rust-only':>9} {'ghidra-only':>11} "
                  f"{'C compared':>10} {'exact':>5} {'median dice':>11}")
        lines += [header, "-" * len(header)]
        for pair in report["pairs"]:
            o, s = pair["overlap"], pair["similarity"]
            dice = s["median_trigram_dice"]
            lines.append(
                f"{pair['case_id']:<20} {pair['repetition']:>3} {o['both']:>5} "
                f"{o['rust_only']:>9} {o['ghidra_only']:>11} {s['compared']:>10} "
                f"{s['normalized_exact']:>5} {('-' if dice is None else f'{dice:.3f}'):>11}"
            )
    lines += ["", "Limitations:"] + [f"- {item}" for item in report.get("limitations", [])]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--ghidra", type=Path)
    parser.add_argument("--truth", type=Path)
    parser.add_argument("--format", choices=("json", "table"), default="table")
    args = parser.parse_args(argv)
    try:
        if args.suite:
            report = compare_suite(args.suite)
        elif args.rust and args.ghidra:
            report = compare_pair(args.rust, args.ghidra, args.truth)
            if args.format == "table":
                parser.error("--format table requires --suite")
        else:
            parser.error("select --suite or both --rust and --ghidra")
    except (InvalidDocument, KeyError, TypeError, OSError) as error:
        print(f"compare-ghidra-benchmark: {error}", file=sys.stderr)
        return 1
    if args.format == "json":
        json.dump(report, sys.stdout, indent=1, allow_nan=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(table(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Summarize complete process traces or certified completed worker requests.

A worker is normally killed by WorkerClient, so its process tail need not finish.
The request_published marker follows terminal encoding/write/flush. It certifies
only that request's preceding phases, provided no records were dropped. Require
an independently received matching terminal reply before interpreting its result.
"""
import argparse
import collections
import json
import math
import pathlib
import statistics

MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000


def read_trace(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"Trace exceeds byte budget: {path.name}")
    records = []
    partial_tail = False
    with path.open("rb") as stream:
        for line in stream:
            if len(line) > 4096 or len(records) == MAX_RECORDS:
                raise ValueError(f"Trace exceeds record budget: {path.name}")
            try:
                record = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                if stream.read(1):
                    raise ValueError(f"Malformed record before end: {path.name}") from None
                partial_tail = True
                break
            if not isinstance(record, dict) or not isinstance(record.get("phase"), str):
                raise ValueError(f"Invalid trace shape: {path.name}")
            if not record["phase"].isascii() or len(record["phase"]) > 80:
                raise ValueError(f"Invalid phase: {path.name}")
            for key in ("pid", "request", "start_us", "elapsed_us", "value", "dropped"):
                if type(record.get(key)) is not int or not 0 <= record[key] < 2**64:
                    raise ValueError(f"Invalid numeric field: {path.name}")
            records.append(record)
    return records, partial_tail


def distribution(values):
    ordered = sorted(values)
    return {"count": len(values), "median_ms": statistics.median(values) / 1000,
            "p95_ms": ordered[math.ceil(len(values) * .95) - 1] / 1000,
            "min_ms": ordered[0] / 1000, "max_ms": ordered[-1] / 1000}


def summarize(path):
    records, partial_tail = read_trace(path)
    started = bool(records) and records[0]["phase"] == "trace_started"
    same_process = len({r["pid"] for r in records}) == 1
    clean = started and same_process
    accepted = []
    published = []
    pending = collections.defaultdict(list)
    for record in records:
        clean &= record["dropped"] == 0 and record["phase"] != "trace_limit_reached"
        pending[record["request"]].append(record)
        if record["phase"] == "request_published":
            request = record["request"]
            result = [r for r in pending[request] if r["phase"] == "request_result_error"]
            certified = (clean and record["value"] == request and len(result) == 1
                         and result[0]["value"] in (0, 1))
            published.append({"request": request, "certified_prefix": bool(certified),
                              "result_error": result[0]["value"] if len(result) == 1 else None})
            if certified:
                accepted.extend(pending[request])
            del pending[request]
    complete = bool(clean and not partial_tail and records
                    and records[-1]["phase"] == "trace_health")
    if complete:
        accepted = records
    phases = collections.defaultdict(list)
    for record in accepted:
        if record["elapsed_us"]:
            phases[record["phase"]].append(record["elapsed_us"])
    return {"file": path.name, "pid": records[0]["pid"] if records else None,
            "process_complete": complete, "partial_tail": partial_tail,
            "records": len(records), "completed_requests": published,
            "includes_failed_requests": any(r["certified_prefix"] and r["result_error"] == 1 for r in published),
            "timing_scope": "complete_process" if complete else "certified_request_prefixes_only",
            "phases": {name: distribution(values) for name, values in sorted(phases.items())}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    paths = sorted(args.directory.glob("trace-*.jsonl"))
    if not paths:
        parser.error("No trace-*.jsonl files found")
    print(json.dumps({"traces": [summarize(path) for path in paths],
                      "limitations": ["Inclusive phases overlap; do not add their durations.",
                                      "Verify each published request against the parent's received terminal reply.",
                                      "Missing process health prevents process-lifetime attribution; completed prefixes remain usable."]}, indent=2))


if __name__ == "__main__":
    main()

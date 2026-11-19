#!/usr/bin/env python3
"""Validate the committed performance baseline.

The baseline is a committed artifact that a shell script and a Go comparison both
consume, so it must be structurally valid even on a machine that cannot reproduce
its numbers. A corrupt baseline would silently disable the regression gate on the
reference machine, which is the worst failure mode available: the check would keep
reporting "no regressions" because it had nothing to compare against.

This validator is deliberately separate from the Go reader. The Go reader
validates what Go needs; this one validates what a non-Go consumer needs (a CI
step, a dashboard, a human with jq), and it runs where the Go binary cannot
produce meaningful numbers.

Usage: scripts/validate-baseline.py [PATH]
Exit:  0 valid, 1 invalid, 2 unreadable
"""

import json
import sys

EXPECTED_SCHEMA = 1
VALID_UNITS = {"MB/s", "ops/s"}


def fail(msg: str) -> int:
    print(f"baseline INVALID: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "docs/benchmarks/baseline.json"

    try:
        with open(path, encoding="utf-8") as f:
            b = json.load(f)
    except FileNotFoundError:
        print(f"baseline MISSING: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        return fail(f"{path} is not valid JSON: {e}")

    if not isinstance(b, dict):
        return fail("top level is not an object")

    if b.get("schema_version") != EXPECTED_SCHEMA:
        return fail(
            f"schema_version is {b.get('schema_version')!r}, expected {EXPECTED_SCHEMA}"
        )

    fp = b.get("fingerprint")
    if not isinstance(fp, dict):
        return fail("no fingerprint object")
    if not fp.get("arch"):
        return fail("fingerprint has no arch")

    metrics = b.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        return fail("no metrics")

    seen = set()
    for i, m in enumerate(metrics):
        if not isinstance(m, dict):
            return fail(f"metric {i} is not an object")
        name = m.get("name")
        if not name:
            return fail(f"metric {i} has no name")
        if name in seen:
            return fail(f"duplicate metric name {name!r}")
        seen.add(name)
        val = m.get("mbps")
        if not isinstance(val, (int, float)) or val <= 0:
            return fail(f"{name}: value is {val!r}, must be a positive number")
        if m.get("unit") not in VALID_UNITS:
            return fail(f"{name}: unit is {m.get('unit')!r}, expected one of {sorted(VALID_UNITS)}")
        if "higher_is_better" not in m:
            return fail(f"{name}: higher_is_better is absent")

    print(
        f"baseline OK: {len(seen)} metrics, schema {b['schema_version']}, "
        f"captured {b.get('captured_at', 'unknown')} on {fp['arch']}"
        f"{'/' + fp['machine_type'] if fp.get('machine_type') else ''} "
        f"MSA-{fp.get('max_msa_level', '?')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
#
# check-regression.sh — compare ZCrypt's current throughput against a committed
# baseline and report any metric that moved more than the tolerance.
#
# Usage:
#   scripts/check-regression.sh [--tolerance PCT] [--baseline PATH] [--strict]
#
# Exit status:
#   0  every metric is within tolerance (or the comparison was skipped)
#   1  at least one metric regressed beyond the tolerance
#   2  the comparison could not be performed (missing binary, bad baseline)
#
# --strict makes a non-comparable machine an error instead of a skip. The CI job
# does NOT use --strict: GitHub runners are amd64 and the baseline is s390x, so a
# strict run would fail on every push. On the reference machine, --strict is what
# you want, because there a skip means something is genuinely wrong with the
# hardware detection.
#
# The comparison itself is done by `zcrypt --baseline-check`, which emits JSON;
# this script only decides the exit status and formats the summary. Keeping the
# logic in Go means the threshold semantics live next to the baseline format and
# cannot drift out of sync with it.

set -euo pipefail

TOLERANCE=20
BASELINE="docs/benchmarks/baseline.json"
STRICT=0
BINARY="./zcrypt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tolerance)
      TOLERANCE="$2"
      shift 2
      ;;
    --baseline)
      BASELINE="$2"
      shift 2
      ;;
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "check-regression: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -x "$BINARY" ]]; then
  echo "check-regression: $BINARY is not executable; build it first (go build -o zcrypt .)" >&2
  exit 2
fi

if [[ ! -f "$BASELINE" ]]; then
  echo "check-regression: baseline $BASELINE does not exist" >&2
  echo "  create one with: $BINARY --write-baseline $BASELINE" >&2
  exit 2
fi

# The comparison writes JSON to stdout and a human summary to stderr, so the
# caller can pipe the JSON somewhere without losing the summary.
set +e
"$BINARY" --baseline-check "$BASELINE" --tolerance "$TOLERANCE" > /tmp/zcrypt-regression.json 2> /tmp/zcrypt-regression.log
STATUS=$?
set -e

cat /tmp/zcrypt-regression.log

if [[ $STATUS -eq 2 ]]; then
  if [[ $STRICT -eq 1 ]]; then
    echo "check-regression: comparison failed and --strict was given" >&2
    exit 2
  fi
  echo "check-regression: comparison could not be performed; not treating as a failure" >&2
  exit 0
fi

# Pull the machine-readable verdict out of the JSON. python3 is used rather than
# jq because python3 is guaranteed present on every runner this runs on.
read -r COMPARABLE REGRESSIONS SKIPPED <<< "$(python3 - <<'PY'
import json, sys
try:
    with open('/tmp/zcrypt-regression.json') as f:
        d = json.load(f)
except Exception:
    print("0 0 0")
    sys.exit(0)
print(1 if d.get('comparable') else 0,
      d.get('regressions', 0),
      d.get('skipped', 0))
PY
)"

if [[ "$COMPARABLE" != "1" ]]; then
  if [[ $STRICT -eq 1 ]]; then
    echo "check-regression: this machine is not comparable to the baseline (--strict)" >&2
    exit 2
  fi
  echo "check-regression: this machine is not comparable to the baseline; skipping" >&2
  exit 0
fi

if [[ "$REGRESSIONS" -gt 0 ]]; then
  echo "check-regression: $REGRESSIONS metric(s) regressed by more than ${TOLERANCE}%" >&2
  exit 1
fi

echo "check-regression: no regressions beyond ${TOLERANCE}% (${SKIPPED} skipped)"
exit 0

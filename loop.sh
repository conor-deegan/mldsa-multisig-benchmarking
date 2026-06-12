#!/usr/bin/env bash
# loop.sh — the whole loop. Fresh context each iteration (state lives in the repo,
# not in the conversation), gated on one objective test. No Stop hook, no state
# machine: the agent sequences its own work; xcheck.rs decides done.
# Run in a container, on the binius-prover branch. ./loop.sh [max_iters]
set -uo pipefail
MAX="${1:-40}"
MODEL="${BINIUS_MODEL:-claude-opus-4-8}"     # sonnet for cheaper mechanical runs
ORACLE='RUSTFLAGS=-Ctarget-cpu=native cargo test -p binius-prover --test xcheck'
PROMPT="$(cat PROMPT.md)"

git rev-parse --abbrev-ref HEAD | grep -qx binius-prover || { echo "be on the binius-prover branch"; exit 1; }

LAST=""
for ((i=1; i<=MAX; i++)); do
  echo "=== iteration $i/$MAX ==="
  claude -p "$PROMPT${LAST:+

The oracle is currently RED. Most recent output:
$LAST}" \
    --model "$MODEL" --dangerously-skip-permissions --output-format text || { sleep $((10*i)); continue; }

  if LAST="$(bash -lc "$ORACLE" 2>&1)"; then
    echo "oracle GREEN — done in $i iterations."; exit 0
  fi
  LAST="$(printf '%s' "$LAST" | tail -c 3000)"
done
echo "hit $MAX iterations without green; inspect the last diff + NOTES.md"; exit 1

#!/bin/bash
set -euo pipefail

NUM_RUNS=10
TARGET_DIR="target-repo"
RESULTS_DIR="results"

echo "=== Claude Security Stochastic Analysis ==="
echo "Target: OWASP Juice Shop"
echo "Runs: $NUM_RUNS"
echo ""

for i in $(seq 1 $NUM_RUNS); do
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUTFILE="${RESULTS_DIR}/scan_run_${i}_${TIMESTAMP}.json"

  echo "--- Run $i of $NUM_RUNS ($(date)) ---"

  # Run Claude Code security review against Juice Shop
  # Use -p (print mode, non-interactive) with explicit output format
  claude -p \
    "You are scanning the codebase in the '${TARGET_DIR}/' directory for security vulnerabilities.
    Perform a thorough security review of the codebase.
    Focus on: injection flaws, authentication bypasses, access control issues,
    XSS, CSRF, insecure deserialization, known vulnerable components,
    security misconfigurations, sensitive data exposure, and broken crypto.

    Output your findings as a JSON array. Each finding must have exactly these fields:
    - id: sequential integer starting at 1
    - category: OWASP Top 10 category (e.g. A01:2021-Broken Access Control)
    - severity: critical/high/medium/low/info
    - title: short title
    - file: relative file path
    - line: line number or null
    - description: 2-3 sentence explanation
    - confidence: high/medium/low
    - cwe: CWE ID if applicable or null

    Return ONLY the JSON array, no markdown fences, no preamble." \
    > "$OUTFILE" 2>"${RESULTS_DIR}/scan_run_${i}_stderr.log"

  echo "    Saved to $OUTFILE"
  echo ""
  sleep 5  # Brief pause between runs
done

echo "=== All $NUM_RUNS runs complete ==="

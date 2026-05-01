# Claude Security Stochastic Analysis

Anthropic launched Claude Security on April 30, 2026. I ran it 10 times on the same codebase to measure consistency. The results: 204 unique findings across 8 valid runs, zero findings in every run, and 90.7% of all findings appeared exactly once.

Full writeup: [Substack article link]

## What this repo contains

```
├── target-repo/              # OWASP Juice Shop source (vulnerability target)
├── results/
│   ├── scan_run_*.json        # Raw JSON output from each Claude Security run
│   └── analysis_report.json   # Aggregated consistency analysis
├── analysis/
│   └── analyze.py             # Python analysis script (stdlib only, zero deps)
├── run-scans.sh               # Bash script to run N consecutive scans
└── README.md
```

## Key findings

| Metric | Value |
|--------|-------|
| Runs analyzed | 8 of 10 attempted |
| Unique findings | 204 |
| Found in all runs | 0 |
| Found in 50%+ of runs | 2 |
| Found in exactly 1 run | 185 (90.7%) |
| Severity drift instances | 4 |
| Findings per run | 18 to 38 (avg 29.1) |

Against Juice Shop's known vulnerability catalogue (~35-40 source-code-detectable vulns), Claude identified approximately 15 distinct true positives across all runs combined. Per-run coverage averaged 40-45%. Entire OWASP categories were missed across all 8 runs: XSS, XXE, prototype pollution.

## Reproduce it yourself

Requirements: Claude Code CLI installed and authenticated, Python 3.8+, Git.

```bash
git clone https://github.com/YOUR_USERNAME/claude-security-experiment.git
cd claude-security-experiment

# Run all scans (expect 30-60 min for 10 runs)
./run-scans.sh

# Analyze results
python3 analysis/analyze.py results/
```

The analysis script uses only Python stdlib. No pip install needed.

## Methodology notes

Each scan used an identical prompt requesting structured JSON output with OWASP category, severity, file path, line number, description, confidence, and CWE mapping. Runs 8 and 10 produced invalid output and were excluded.

There is a known path normalization artifact: Claude inconsistently prefixed file paths with `target-repo/` across runs. The analysis script treats these as separate findings, inflating the unique count. After manual normalization the true unique count is closer to 150-170, but the core finding (zero 100% detection rate) holds.

See the [Substack article](LINK) for full methodology, ground truth cross-reference against known Juice Shop vulnerabilities, limitations, and next steps.

## License

Analysis scripts and documentation: MIT. OWASP Juice Shop is licensed separately under MIT by Bjoern Kimminich and contributors.

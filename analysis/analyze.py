#!/usr/bin/env python3
"""Analyze consistency across multiple Claude Security scan runs."""

import json
import glob
import sys
from collections import Counter, defaultdict
from pathlib import Path

def load_results(results_dir: str) -> list[tuple[str, list[dict]]]:
    """Load all scan result JSON files."""
    runs = []
    for filepath in sorted(glob.glob(f"{results_dir}/scan_run_*.json")):
        try:
            with open(filepath) as f:
                raw = f.read().strip()
                # Handle potential markdown fences
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                data = json.loads(raw)
                if isinstance(data, list):
                    runs.append((Path(filepath).name, data))
                else:
                    print(f"WARNING: {filepath} is not a JSON array, skipping")
        except (json.JSONDecodeError, Exception) as e:
            print(f"WARNING: Failed to parse {filepath}: {e}")
    return runs


def normalize_finding(finding: dict) -> str:
    """Create a normalized key for deduplication across runs."""
    # Use file + category + title as the identity key
    f = finding.get("file", "unknown")
    cat = finding.get("category", "unknown")
    title = finding.get("title", "unknown").lower().strip()
    return f"{f}::{cat}::{title}"


def analyze(runs: list[tuple[str, list[dict]]]) -> dict:
    """Core analysis: consistency, severity drift, coverage."""
    num_runs = len(runs)
    finding_runs = defaultdict(list)  # normalized_key -> list of run indices
    finding_details = {}  # normalized_key -> first occurrence details
    severity_by_finding = defaultdict(list)  # normalized_key -> list of severities
    confidence_by_finding = defaultdict(list)

    for run_idx, (filename, findings) in enumerate(runs):
        for f in findings:
            key = normalize_finding(f)
            finding_runs[key].append(run_idx)
            severity_by_finding[key].append(f.get("severity", "unknown"))
            confidence_by_finding[key].append(f.get("confidence", "unknown"))
            if key not in finding_details:
                finding_details[key] = f

    # Consistency buckets
    always = []  # found in all runs
    frequent = []  # found in 50-99% of runs
    sporadic = []  # found in <50% of runs
    once = []  # found in exactly 1 run

    for key, run_indices in finding_runs.items():
        count = len(run_indices)
        detail = finding_details[key]
        entry = {
            "key": key,
            "title": detail.get("title"),
            "file": detail.get("file"),
            "category": detail.get("category"),
            "appearances": count,
            "appearance_rate": f"{count}/{num_runs}",
            "severities_seen": list(set(severity_by_finding[key])),
            "severity_drift": len(set(severity_by_finding[key])) > 1,
            "confidences_seen": list(set(confidence_by_finding[key])),
        }
        if count == num_runs:
            always.append(entry)
        elif count >= num_runs * 0.5:
            frequent.append(entry)
        elif count == 1:
            once.append(entry)
        else:
            sporadic.append(entry)

    # Per-run stats
    run_stats = []
    for run_idx, (filename, findings) in enumerate(runs):
        run_stats.append({
            "run": filename,
            "total_findings": len(findings),
            "by_severity": dict(Counter(f.get("severity", "unknown") for f in findings)),
            "by_category": dict(Counter(f.get("category", "unknown") for f in findings)),
        })

    # Severity drift count
    drift_count = sum(1 for key in finding_runs if len(set(severity_by_finding[key])) > 1)

    return {
        "summary": {
            "total_runs": num_runs,
            "unique_findings_across_all_runs": len(finding_runs),
            "findings_in_all_runs": len(always),
            "findings_in_50pct_plus": len(frequent),
            "findings_in_under_50pct": len(sporadic),
            "findings_in_exactly_1_run": len(once),
            "findings_with_severity_drift": drift_count,
            "min_findings_per_run": min(r["total_findings"] for r in run_stats),
            "max_findings_per_run": max(r["total_findings"] for r in run_stats),
            "avg_findings_per_run": round(
                sum(r["total_findings"] for r in run_stats) / num_runs, 1
            ),
        },
        "consistency_buckets": {
            "always_detected": sorted(always, key=lambda x: x["title"]),
            "frequently_detected": sorted(frequent, key=lambda x: x["appearances"], reverse=True),
            "sporadically_detected": sorted(sporadic, key=lambda x: x["appearances"], reverse=True),
            "detected_once_only": sorted(once, key=lambda x: x["title"]),
        },
        "per_run_stats": run_stats,
    }


def print_report(analysis: dict):
    """Print human-readable report."""
    s = analysis["summary"]
    print("=" * 70)
    print("CLAUDE SECURITY STOCHASTIC ANALYSIS REPORT")
    print("=" * 70)
    print(f"\nRuns analyzed: {s['total_runs']}")
    print(f"Unique findings across all runs: {s['unique_findings_across_all_runs']}")
    print(f"Findings per run: min={s['min_findings_per_run']}, "
          f"max={s['max_findings_per_run']}, avg={s['avg_findings_per_run']}")
    print(f"\nConsistency breakdown:")
    print(f"  Always detected (100%):    {s['findings_in_all_runs']}")
    print(f"  Frequently detected (50%+): {s['findings_in_50pct_plus']}")
    print(f"  Sporadic (<50%):            {s['findings_in_under_50pct']}")
    print(f"  One-off (single run):       {s['findings_in_exactly_1_run']}")
    print(f"\nSeverity drift (same finding, different severity): "
          f"{s['findings_with_severity_drift']}")

    buckets = analysis["consistency_buckets"]
    for label, items in buckets.items():
        if items:
            print(f"\n--- {label.upper().replace('_', ' ')} ---")
            for item in items[:15]:  # Cap output
                drift_flag = " [SEVERITY DRIFT]" if item["severity_drift"] else ""
                print(f"  [{item['appearances']}/{s['total_runs']}] "
                      f"{item['title']} ({item['file']}) "
                      f"sev={item['severities_seen']}{drift_flag}")


if __name__ == "__main__":
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "results"
    runs = load_results(results_dir)

    if len(runs) < 2:
        print(f"ERROR: Need at least 2 valid scan results in {results_dir}/")
        sys.exit(1)

    result = analyze(runs)
    print_report(result)

    # Save full analysis as JSON
    output_path = f"{results_dir}/analysis_report.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nFull report saved to {output_path}")

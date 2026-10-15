"""
run_pipeline.py
===============
Master runner — executes Steps 2, 3, 4 in sequence:
  1. build_dataset.py   — feature extraction & labelled dataset
  2. splitter.py        — 5 split strategies
  3. benchmark_models.py — model training & evaluation
  4. final_report.py    — consolidated research findings report

Run from project root:
  python scripts/run_pipeline.py
"""

import subprocess
import sys
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")

PIPELINE = [
    ("Step 1: Build Labelled Dataset",          "build_dataset.py"),
    ("Step 2: Generate Domain-Disjoint Splits",  "splitter.py"),
    ("Step 3: Benchmark Models",                 "benchmark_models.py"),
]

def run_step(label, script):
    script_path = os.path.join(SCRIPTS, script)
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    t0 = time.time()
    result = subprocess.run([sys.executable, script_path],
                            capture_output=False, text=True)
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"\n[ERROR] {script} failed (exit {result.returncode}).")
        sys.exit(result.returncode)
    print(f"\n  Completed in {elapsed:.1f}s")

if __name__ == "__main__":
    print("\nPhishGuard-Eval: Full Pipeline Runner")
    print("=" * 60)
    start = time.time()
    for label, script in PIPELINE:
        run_step(label, script)
    total = time.time() - start
    print(f"\n{'='*60}")
    print(f"  ALL STEPS COMPLETE  ({total:.1f}s total)")
    print(f"{'='*60}")
    print("\nOutputs:")
    print("  data/processed/dataset.csv       — labelled feature matrix")
    print("  data/splits/*_train/test.csv     — 5 split strategies")
    print("  docs/benchmark_results.json      — raw metrics")
    print("  docs/benchmark_report.md         — research findings report")
    print("  docs/figures/                    — charts")

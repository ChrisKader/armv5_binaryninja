#!/usr/bin/env python3
"""
Test script to measure the impact of prologue body validation.

This loads nspire.bin and reports detection statistics including
how many functions were rescued by body validation.

Usage:
    python test_body_validation.py [--cached|--fresh]

    --cached  Load existing bndb without re-analysis (default if plugin unchanged)
    --fresh   Force fresh analysis even if bndb exists (use when testing plugin changes)

Default behavior: Fresh analysis if no bndb exists, otherwise use cached.
"""

import sys
import time
from pathlib import Path

# Unbuffered stdout for real-time output
sys.stdout.reconfigure(line_buffering=True)

# Add Binary Ninja Python path
sys.path.insert(0, "/Applications/Binary Ninja DEV.app/Contents/Resources/python")

import binaryninja as bn
from binaryninja import BackgroundTask

# Enable logging to stdout and file
LOG_FILE = Path("/Users/ck/dev/armv5_binaryninja/bnlog.log")
bn.log_to_stdout(bn.LogLevel.InfoLog)
bn.log_to_file(bn.LogLevel.InfoLog, str(LOG_FILE))

def find_armv5_task():
    """Find the running ARMv5 firmware scan task."""
    for task in BackgroundTask:
        progress = task.progress or ""
        if "ARMv5" in progress and not task.finished:
            return task
    return None

def wait_for_analysis(view, timeout=300):
    """Wait for analysis to complete, showing progress."""
    print("Waiting for analysis to complete...")
    start = time.time()
    last_progress = ""

    while time.time() - start < timeout:
        # Check for ARMv5 task
        task = find_armv5_task()
        if task:
            progress = task.progress or ""
            if progress != last_progress:
                print(f"  {progress}")
                last_progress = progress

        # Check if analysis is idle
        if view.analysis_info.state == bn.AnalysisState.IdleState:
            # Double-check no ARMv5 task is running
            task = find_armv5_task()
            if not task:
                print(f"Analysis complete in {time.time() - start:.1f}s")
                return True

        time.sleep(0.5)

    print(f"Timeout after {timeout}s")
    return False

def main():
    binary_path = Path("/Users/ck/dev/armv5_binaryninja/data/nspire/cxii_cas_6.2.0.333/binaries/nspire.bin")
    bndb_path = binary_path.with_suffix(".bndb")

    # Parse command-line arguments
    force_fresh = "--fresh" in sys.argv
    force_cached = "--cached" in sys.argv

    if force_fresh and force_cached:
        print("ERROR: Cannot specify both --fresh and --cached")
        return 1

    print(f"Testing body validation on: {binary_path.name}")
    print("=" * 60)

    # Determine whether to use cached bndb
    # Default: use cached if exists, unless --fresh specified
    use_cached = bndb_path.exists() and not force_fresh

    if use_cached:
        print(f"Loading cached analysis from {bndb_path.name}...")
        print("  (Use --fresh to force re-analysis)")
        view = bn.load(str(bndb_path), update_analysis=False)
        if not view:
            print("ERROR: Failed to load bndb")
            return 1
    else:
        if force_fresh and bndb_path.exists():
            print(f"Deleting existing {bndb_path.name} for fresh analysis...")
            bndb_path.unlink()

        print(f"Loading {binary_path.name} with fresh analysis...")
        view = bn.load(str(binary_path))

        if not view:
            print("ERROR: Failed to load binary")
            return 1

        # Wait for analysis
        if not wait_for_analysis(view):
            print("WARNING: Analysis may not be complete")

    # Get function statistics
    functions = list(view.functions)
    print(f"\nResults:")
    print(f"  Total functions detected: {len(functions)}")

    # Count ARM vs Thumb
    arm_count = sum(1 for f in functions if not f.arch.name.endswith('t'))
    thumb_count = len(functions) - arm_count
    print(f"  ARM functions: {arm_count}")
    print(f"  Thumb functions: {thumb_count}")

    # Check the Binary Ninja log for body validation stats
    # The FunctionDetector logs: "Found %zu candidates (high=%zu, med=%zu, low=%zu, body-validated=%zu)"
    print("\nCheck bnlog.log for body validation statistics:")
    print("  grep 'body-validated' bnlog.log")

    # Save for future runs (only if we did fresh analysis)
    if not use_cached:
        print(f"\nSaving to {bndb_path.name}...")
        view.file.create_database(str(bndb_path))
        print("Saved.")

    view.file.close()
    print("\nDone!")
    return 0

if __name__ == "__main__":
    sys.exit(main())

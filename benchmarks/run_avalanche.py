#!/usr/bin/env python3
"""Avalanche-effect benchmark.

For each algorithm, takes a baseline payload, flips exactly one random
bit, hashes both versions, and reports the Hamming distance between the
output digests.  A cryptographically strong hash should yield ≈50 % bit
variance (the *strict avalanche criterion*).

Exports results to ``data/avalanche.csv``.

Usage::

    uv run python -m benchmarks.run_avalanche
"""

from __future__ import annotations

import csv
import os
import time
from pathlib import Path

from src.algorithms import ALGORITHMS, ALGORITHM_NAMES
from src.avalanche import AvalancheResult, measure_avalanche

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PAYLOAD_SIZES: list[int] = [
    64,                  # minimal block
    1 * 1024,            # 1 KB
    100 * 1024,          # 100 KB
    1 * 1024 * 1024,     # 1 MB
]

TRIALS_PER_SIZE: int = 20
"""Number of independent single-bit-flip trials per (algorithm, size) pair."""

SCRYPT_MAX_PAYLOAD: int = 1 * 1024 * 1024

CSV_HEADER: list[str] = [
    "timestamp",
    "algorithm",
    "payload_bytes",
    "trial",
    "flipped_bit_index",
    "hamming_distance",
    "total_bits",
    "avalanche_ratio",
]


def _ensure_data_dir() -> Path:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def run() -> list[AvalancheResult]:
    """Execute the full avalanche-effect test suite."""
    results: list[AvalancheResult] = []
    data_dir = _ensure_data_dir()
    csv_path = data_dir / "avalanche.csv"

    write_header = not csv_path.exists()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(CSV_HEADER)

        for algo_name in ALGORITHM_NAMES:
            func = ALGORITHMS[algo_name]
            for size in PAYLOAD_SIZES:
                if algo_name == "scrypt" and size > SCRYPT_MAX_PAYLOAD:
                    continue

                payload = os.urandom(size)
                ratios: list[float] = []

                for trial in range(TRIALS_PER_SIZE):
                    result = measure_avalanche(func, payload, algo_name)
                    results.append(result)
                    ratios.append(result.avalanche_ratio)

                    writer.writerow([
                        time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        result.algorithm,
                        result.payload_bytes,
                        trial + 1,
                        result.flipped_bit_index,
                        result.hamming_distance,
                        result.total_bits,
                        f"{result.avalanche_ratio:.6f}",
                    ])

                fh.flush()
                mean_ratio = sum(ratios) / len(ratios)

                print(
                    f"  {algo_name:<10s} | "
                    f"{size:>10,d} B | "
                    f"mean avalanche = {mean_ratio:.4f} "
                    f"({'PASS ✓' if 0.35 <= mean_ratio <= 0.65 else 'WARN ⚠'})"
                )

    print(f"\n✓ Results appended to {csv_path}")
    return results


def main() -> None:
    """CLI entry point."""
    print("=" * 66)
    print("CipherChain — Avalanche Effect Benchmark")
    print("=" * 66)
    run()


if __name__ == "__main__":
    main()


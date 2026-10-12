#!/usr/bin/env python3
"""Throughput & latency benchmark.

Loops dynamically sized payloads (1 KB → 100 MB) across all four hash
algorithms, measures MB/s throughput, and appends results to
``data/throughput.csv``.

Usage::

    uv run python -m benchmarks.run_throughput
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import sys
import time
from pathlib import Path

from src.algorithms import ALGORITHMS, ALGORITHM_NAMES
from src.metrics import TimingResult, measure_latency

# ---------------------------------------------------------------------------
# Payload sizes (bytes)
# ---------------------------------------------------------------------------
PAYLOAD_SIZES: list[int] = [
    1 * 1024,            # 1 KB
    10 * 1024,           # 10 KB
    100 * 1024,          # 100 KB
    1 * 1024 * 1024,     # 1 MB
    10 * 1024 * 1024,    # 10 MB
    100 * 1024 * 1024,   # 100 MB
]

# Scrypt is a KDF — its cost is dominated by CPU/memory work, not input
# length.  Feeding it 100 MB payloads takes unreasonably long and isn't
# a meaningful throughput test, so we cap scrypt payloads at 1 MB.
SCRYPT_MAX_PAYLOAD: int = 1 * 1024 * 1024

# Number of iterations per measurement (higher → less noise).
# Small payloads get more iterations to amortise timer overhead.
MIN_BENCH_TIME_SECS: float = 0.5

CSV_HEADER: list[str] = [
    "timestamp",
    "node",
    "algorithm",
    "payload_bytes",
    "elapsed_seconds",
    "throughput_mb_per_sec",
]


def _iterations_for(payload_bytes: int) -> int:
    """Return iteration count that targets ≈ MIN_BENCH_TIME_SECS total."""
    # Rough heuristic: 1 KB → 5000 iters, 100 MB → 1 iter
    estimated_per_call = payload_bytes / (500 * 1024 * 1024)  # assume ~500 MB/s
    iters = max(1, int(MIN_BENCH_TIME_SECS / max(estimated_per_call, 1e-9)))
    return min(iters, 10_000)


def _ensure_data_dir() -> Path:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def run(node: str | None = None) -> list[TimingResult]:
    """Execute the full throughput benchmark suite."""
    node_id = node or platform.node() or "unknown"
    results: list[TimingResult] = []
    data_dir = _ensure_data_dir()
    csv_path = data_dir / "throughput.csv"

    write_header = not csv_path.exists()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(CSV_HEADER)

        for algo_name in ALGORITHM_NAMES:
            func = ALGORITHMS[algo_name]
            for size in PAYLOAD_SIZES:
                # Skip oversized payloads for scrypt
                if algo_name == "scrypt" and size > SCRYPT_MAX_PAYLOAD:
                    continue

                payload = os.urandom(size)
                iters = _iterations_for(size)
                if algo_name == "scrypt":
                    # Scrypt is orders of magnitude slower — use 1 iteration
                    iters = 1

                result = measure_latency(
                    func, payload, algo_name, iterations=iters
                )
                results.append(result)

                writer.writerow([
                    time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    node_id,
                    result.algorithm,
                    result.payload_bytes,
                    f"{result.elapsed_seconds:.9f}",
                    f"{result.throughput_mb_per_sec:.4f}",
                ])
                fh.flush()

                print(
                    f"  [{node_id}] {algo_name:<10s} | "
                    f"{size / 1024:>10.0f} KB | "
                    f"{result.elapsed_seconds * 1000:>10.3f} ms | "
                    f"{result.throughput_mb_per_sec:>10.2f} MB/s"
                )

    print(f"\n✓ Results appended to {csv_path}")
    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CipherChain — Throughput & Latency Benchmark"
    )
    parser.add_argument(
        "--node",
        "--machine-id",
        dest="node",
        type=str,
        default=platform.node() or "unknown",
        help="Hardware node identifier (default: platform.node()).",
    )
    args = parser.parse_args()

    print("=" * 66)
    print(f"CipherChain — Throughput & Latency Benchmark [Node: {args.node}]")
    print("=" * 66)
    run(node=args.node)


if __name__ == "__main__":
    main()



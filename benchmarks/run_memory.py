#!/usr/bin/env python3
"""Memory-profiling benchmark.

Profiles peak RAM allocation during hashing to empirically demonstrate
Scrypt's memory-hardness versus SHA-256's low footprint. Measures both
standard streaming hashes across payload sizes and Scrypt with scaled
cost parameters (N=16384, r=8 for ~16 MiB and N=32768, r=8 for ~32 MiB).

Exports results to ``data/memory.csv``.

Usage::

    uv run python -m benchmarks.run_memory
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import time
from pathlib import Path

from src.algorithms import (
    ALGORITHMS,
    ALGORITHM_NAMES,
    hash_scrypt,
    scrypt_theoretical_memory,
)
from src.metrics import MemoryResult, measure_memory

# ---------------------------------------------------------------------------
# Payload sizes for baseline memory profiling across algorithms
# ---------------------------------------------------------------------------
PAYLOAD_SIZES: list[int] = [
    1 * 1024,            # 1 KB
    100 * 1024,          # 100 KB
    1 * 1024 * 1024,     # 1 MB
    10 * 1024 * 1024,    # 10 MB
]

SCRYPT_MAX_PAYLOAD: int = 1 * 1024 * 1024

# ---------------------------------------------------------------------------
# Scaled Scrypt cost parameter configurations for explicit memory hardness
# Theoretical RAM: 128 * r * N bytes
# ---------------------------------------------------------------------------
SCRYPT_HARDNESS_CONFIGS: list[tuple[int, int, int]] = [
    (16384, 8, 1),  # 128 * 8 * 16384 = 16,777,216 bytes (16 MiB)
    (32768, 8, 1),  # 128 * 8 * 32768 = 33,554,432 bytes (32 MiB)
]

CSV_HEADER: list[str] = [
    "timestamp",
    "node",
    "algorithm",
    "payload_bytes",
    "baseline_memory_mib",
    "peak_memory_mib",
    "delta_memory_mib",
    "theoretical_memory_bytes",
]


def _ensure_data_dir() -> Path:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def run(node: str | None = None) -> list[MemoryResult]:
    """Execute the full memory-profiling suite."""
    node_id = node or platform.node() or "unknown"
    results: list[MemoryResult] = []
    data_dir = _ensure_data_dir()
    csv_path = data_dir / "memory.csv"

    write_header = not csv_path.exists()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(CSV_HEADER)

        print(f"\n--- Part 1: Baseline Memory Profile Across Algorithms [{node_id}] ---")
        for algo_name in ALGORITHM_NAMES:
            func = ALGORITHMS[algo_name]
            for size in PAYLOAD_SIZES:
                if algo_name == "scrypt" and size > SCRYPT_MAX_PAYLOAD:
                    continue

                payload = os.urandom(size)
                # Theoretical footprint: baseline scrypt is 128*1*1024 = 131,072 bytes; others ~0
                theo_bytes = scrypt_theoretical_memory(1024, 1) if algo_name == "scrypt" else 0

                result = measure_memory(
                    func,
                    payload,
                    algo_name,
                    theoretical_memory_bytes=theo_bytes,
                )
                results.append(result)

                writer.writerow([
                    time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    node_id,
                    result.algorithm,
                    result.payload_bytes,
                    f"{result.baseline_memory_mib:.4f}",
                    f"{result.peak_memory_mib:.4f}",
                    f"{result.delta_memory_mib:.4f}",
                    result.theoretical_memory_bytes,
                ])
                fh.flush()

                theo_str = (
                    f" (theo {theo_bytes / (1024 * 1024):.2f} MiB)"
                    if theo_bytes > 0
                    else ""
                )
                print(
                    f"  [{node_id}] {algo_name:<10s} | "
                    f"{size / 1024:>8.0f} KB | "
                    f"baseline {result.baseline_memory_mib:>8.2f} MiB | "
                    f"peak {result.peak_memory_mib:>8.2f} MiB | "
                    f"Δ {result.delta_memory_mib:>+8.4f} MiB{theo_str}"
                )

        print(f"\n--- Part 2: Scrypt Scaled Memory-Hardness Benchmark [{node_id}] ---")
        scrypt_payload = os.urandom(1024)  # 1 KB payload isolates cost-parameter allocation
        for n, r, p in SCRYPT_HARDNESS_CONFIGS:
            theo_bytes = scrypt_theoretical_memory(n, r)
            theo_mib = theo_bytes / (1024 * 1024)

            # Profile Scrypt with scaled cost parameters
            scrypt_func = lambda d, n_val=n, r_val=r, p_val=p: hash_scrypt(
                d, n=n_val, r=r_val, p=p_val
            )

            result = measure_memory(
                scrypt_func,
                scrypt_payload,
                "scrypt",
                theoretical_memory_bytes=theo_bytes,
            )
            results.append(result)

            writer.writerow([
                time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                node_id,
                result.algorithm,
                result.payload_bytes,
                f"{result.baseline_memory_mib:.4f}",
                f"{result.peak_memory_mib:.4f}",
                f"{result.delta_memory_mib:.4f}",
                result.theoretical_memory_bytes,
            ])
            fh.flush()

            print(
                f"  [{node_id}] scrypt (N={n}, r={r}) | "
                f"theo {theo_mib:>5.1f} MiB | "
                f"baseline {result.baseline_memory_mib:>8.2f} MiB | "
                f"peak {result.peak_memory_mib:>8.2f} MiB | "
                f"Δ {result.delta_memory_mib:>+8.4f} MiB "
                f"({'PASS ✓' if abs(result.delta_memory_mib - theo_mib) < 2.0 else 'WARN ⚠'})"
            )

    print(f"\n✓ Results appended to {csv_path}")
    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CipherChain — Memory Profiling Benchmark"
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

    print("=" * 70)
    print(f"CipherChain — Memory Profiling Benchmark [Node: {args.node}]")
    print("=" * 70)
    run(node=args.node)


if __name__ == "__main__":
    main()


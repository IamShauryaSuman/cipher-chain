"""High-resolution timing and memory-profiling utilities.

All timing uses ``time.perf_counter`` (sub-µs resolution on modern Linux)
and all memory tracking uses ``memory_profiler.memory_usage`` so results
are comparable across machines.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from memory_profiler import memory_usage  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class TimingResult:
    """Immutable record of a single timing measurement."""

    algorithm: str
    payload_bytes: int
    elapsed_seconds: float
    throughput_mb_per_sec: float


@dataclass(frozen=True, slots=True)
class MemoryResult:
    """Immutable record of a single memory-profiling run."""

    algorithm: str
    payload_bytes: int
    peak_memory_mib: float
    baseline_memory_mib: float
    delta_memory_mib: float
    theoretical_memory_bytes: int = 0


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------
def measure_latency(
    func: Callable[[bytes], str],
    data: bytes,
    algorithm_name: str,
    *,
    iterations: int = 1,
) -> TimingResult:
    """Time *func(data)* over *iterations* and return throughput stats.

    Args:
        func: Hash function to benchmark.
        data: Payload bytes to feed the function.
        algorithm_name: Label for the result record.
        iterations: Number of repetitions (the total elapsed time is
            divided by this to yield per-call latency).

    Returns:
        A ``TimingResult`` containing elapsed time and MB/s throughput.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        func(data)
    end = time.perf_counter()

    elapsed = (end - start) / iterations
    payload_mb = len(data) / (1024 * 1024)
    throughput = payload_mb / elapsed if elapsed > 0 else float("inf")

    return TimingResult(
        algorithm=algorithm_name,
        payload_bytes=len(data),
        elapsed_seconds=elapsed,
        throughput_mb_per_sec=throughput,
    )


# ---------------------------------------------------------------------------
# Memory helpers
# ---------------------------------------------------------------------------
def measure_memory(
    func: Callable[[bytes], str],
    data: bytes,
    algorithm_name: str,
    *,
    theoretical_memory_bytes: int = 0,
    interval: float = 0.002,
) -> MemoryResult:
    """Profile peak RSS while executing *func(data)*.

    ``memory_profiler.memory_usage`` samples the process's RSS at a
    configurable interval.  We capture a baseline *before* the call and
    then the peak *during* the call.

    Args:
        func: Hash function to benchmark.
        data: Payload bytes.
        algorithm_name: Label for the result record.
        theoretical_memory_bytes: Theoretical memory requirement (e.g., 128*r*N).
        interval: Sampling interval in seconds (default: 0.002 = 2 ms).

    Returns:
        A ``MemoryResult`` with baseline, peak, and delta in MiB.
    """
    # Baseline: measure RSS with a no-op
    baseline_samples: list[float] = memory_usage(
        (lambda: None, (), {}),
        interval=interval,
        max_usage=True,
        retval=False,
        max_iterations=1,
    )
    baseline: float = (
        baseline_samples
        if isinstance(baseline_samples, (int, float))
        else max(baseline_samples)  # type: ignore[arg-type]
    )

    # Profiled run
    peak_samples: list[float] = memory_usage(
        (func, (data,), {}),
        interval=interval,
        max_usage=True,
        retval=False,
        max_iterations=1,
    )
    peak: float = (
        peak_samples
        if isinstance(peak_samples, (int, float))
        else max(peak_samples)  # type: ignore[arg-type]
    )

    delta = max(0.0, float(peak) - float(baseline))

    return MemoryResult(
        algorithm=algorithm_name,
        payload_bytes=len(data),
        peak_memory_mib=float(peak),
        baseline_memory_mib=float(baseline),
        delta_memory_mib=delta,
        theoretical_memory_bytes=theoretical_memory_bytes,
    )


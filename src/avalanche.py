"""Avalanche-effect analysis.

Implements a strict mathematical test: given a baseline payload, flip
exactly one random bit, hash both versions, and compute the Hamming
distance between the two output digests to verify ≈50 % bit variance.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AvalancheResult:
    """Immutable record of a single avalanche-effect measurement."""

    algorithm: str
    payload_bytes: int
    flipped_bit_index: int
    hamming_distance: int
    total_bits: int
    avalanche_ratio: float


# ---------------------------------------------------------------------------
# Bit manipulation helpers
# ---------------------------------------------------------------------------
def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Return a copy of *data* with exactly one bit flipped.

    Args:
        data: Original payload.
        bit_index: Zero-based index of the bit to flip (0 is the MSB of
            the first byte).

    Returns:
        A new ``bytes`` object identical to *data* except at *bit_index*.

    Raises:
        IndexError: If *bit_index* ≥ len(data) * 8.
    """
    total_bits = len(data) * 8
    if bit_index < 0 or bit_index >= total_bits:
        raise IndexError(
            f"bit_index {bit_index} out of range for {total_bits}-bit payload"
        )

    byte_index, bit_offset = divmod(bit_index, 8)
    mask = 1 << (7 - bit_offset)  # MSB-first ordering

    mutated = bytearray(data)
    mutated[byte_index] ^= mask
    return bytes(mutated)


def hamming_distance_hex(hex_a: str, hex_b: str) -> int:
    """Compute the bit-level Hamming distance between two hex-digest strings.

    Args:
        hex_a: First hex-encoded hash digest.
        hex_b: Second hex-encoded hash digest (must be the same length).

    Returns:
        Number of differing bits.

    Raises:
        ValueError: If the digests differ in length.
    """
    if len(hex_a) != len(hex_b):
        raise ValueError(
            f"Digest length mismatch: {len(hex_a)} vs {len(hex_b)}"
        )

    bytes_a = bytes.fromhex(hex_a)
    bytes_b = bytes.fromhex(hex_b)

    return sum(bin(a ^ b).count("1") for a, b in zip(bytes_a, bytes_b))


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------
def measure_avalanche(
    func: Callable[[bytes], str],
    data: bytes,
    algorithm_name: str,
    *,
    bit_index: int | None = None,
) -> AvalancheResult:
    """Run a single avalanche-effect trial.

    Args:
        func: Hash function under test.
        data: Baseline payload.
        algorithm_name: Label for the result record.
        bit_index: Specific bit to flip.  If ``None`` a uniformly random
            bit is chosen.

    Returns:
        An ``AvalancheResult`` containing the Hamming distance and the
        avalanche ratio (distance / total output bits).
    """
    if bit_index is None:
        bit_index = random.randint(0, len(data) * 8 - 1)

    mutated = flip_bit(data, bit_index)

    digest_original = func(data)
    digest_mutated = func(mutated)

    distance = hamming_distance_hex(digest_original, digest_mutated)
    total_bits = len(bytes.fromhex(digest_original)) * 8
    ratio = distance / total_bits if total_bits > 0 else 0.0

    return AvalancheResult(
        algorithm=algorithm_name,
        payload_bytes=len(data),
        flipped_bit_index=bit_index,
        hamming_distance=distance,
        total_bits=total_bits,
        avalanche_ratio=ratio,
    )


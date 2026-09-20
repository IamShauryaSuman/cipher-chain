"""Wrapper functions for the four target hashlib algorithms.

Each function accepts raw ``bytes`` and returns a deterministic hex-digest
string. The API is intentionally uniform so callers can treat all four
algorithms as interchangeable ``Callable[[bytes], str]``.
"""

from __future__ import annotations

import hashlib
from typing import Callable

# ---------------------------------------------------------------------------
# Type alias shared across the codebase
# ---------------------------------------------------------------------------
HashFunction = Callable[[bytes], str]

# ---------------------------------------------------------------------------
# Canonical algorithm registry
# ---------------------------------------------------------------------------
ALGORITHM_NAMES: list[str] = ["sha256", "sha3_256", "scrypt", "blake2b"]
"""Ordered list of algorithm identifiers used in every benchmark script."""


def hash_sha256(data: bytes) -> str:
    """SHA-256 (Merkle-Damgård construction).

    Args:
        data: Arbitrary-length payload to hash.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(data).hexdigest()


def hash_sha3_256(data: bytes) -> str:
    """SHA3-256 / Keccak-256 (Sponge construction).

    Args:
        data: Arbitrary-length payload to hash.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha3_256(data).hexdigest()


def hash_scrypt(
    data: bytes,
    *,
    n: int = 1024,
    r: int = 1,
    p: int = 1,
    maxmem: int = 0,
    dklen: int = 32,
) -> str:
    """Scrypt (Memory-hard Password-Based Key Derivation Function).

    Uses a fixed empty salt for reproducible benchmarking — **not** for
    production credential storage.

    Args:
        data: Input keying material.
        n: CPU/memory cost parameter (must be a power of 2).
        r: Block-size parameter.
        p: Parallelisation parameter.
        maxmem: Maximum memory ``scrypt`` is allowed to use (0 = default).
        dklen: Length of the derived key in bytes.

    Returns:
        Hex-encoded derived key.
    """
    theoretical = 128 * r * n
    effective_maxmem = maxmem if maxmem > 0 else max(33554432, theoretical * 2)
    return hashlib.scrypt(
        data,
        salt=b"",
        n=n,
        r=r,
        p=p,
        maxmem=effective_maxmem,
        dklen=dklen,
    ).hex()


def scrypt_theoretical_memory(n: int, r: int) -> int:
    """Calculate the theoretical RAM footprint for Scrypt in bytes: 128 * r * N.

    Args:
        n: CPU/memory cost parameter.
        r: Block size parameter.

    Returns:
        Theoretical scratchpad memory allocation in bytes.
    """
    return 128 * r * n


def hash_blake2b(data: bytes) -> str:
    """BLAKE2b (ARX — Addition-Rotation-XOR architecture).

    Uses the default 64-byte digest for maximum throughput.

    Args:
        data: Arbitrary-length payload to hash.

    Returns:
        128-character lowercase hex digest.
    """
    return hashlib.blake2b(data).hexdigest()


# ---------------------------------------------------------------------------
# Registry mapping algorithm name → callable
# ---------------------------------------------------------------------------
ALGORITHMS: dict[str, HashFunction] = {
    "sha256": hash_sha256,
    "sha3_256": hash_sha3_256,
    "scrypt": hash_scrypt,
    "blake2b": hash_blake2b,
}
"""Look-up table consumed by every benchmark runner and test."""


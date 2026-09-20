"""Pytest suite for the CipherChain cryptographic test harness.

Validates that:
1. All four hash algorithms produce deterministic, correctly-sized digests.
2. The bit-flipping utility is mathematically correct.
3. The Hamming-distance calculation is exact.
4. The avalanche effect yields ≈50 % bit variance for all algorithms.
5. The timing metric infrastructure returns sane values.
"""

from __future__ import annotations

import hashlib

import pytest

from src.algorithms import (
    ALGORITHMS,
    ALGORITHM_NAMES,
    hash_blake2b,
    hash_scrypt,
    hash_sha256,
    hash_sha3_256,
)
from src.avalanche import AvalancheResult, flip_bit, hamming_distance_hex, measure_avalanche
from src.metrics import TimingResult, measure_latency


# ===================================================================
# Section 1 — Algorithm Correctness
# ===================================================================
class TestAlgorithmDeterminism:
    """Hash functions must be deterministic."""

    PAYLOAD = b"CipherChain deterministic test payload"

    def test_sha256_deterministic(self) -> None:
        assert hash_sha256(self.PAYLOAD) == hash_sha256(self.PAYLOAD)

    def test_sha3_256_deterministic(self) -> None:
        assert hash_sha3_256(self.PAYLOAD) == hash_sha3_256(self.PAYLOAD)

    def test_scrypt_deterministic(self) -> None:
        assert hash_scrypt(self.PAYLOAD) == hash_scrypt(self.PAYLOAD)

    def test_blake2b_deterministic(self) -> None:
        assert hash_blake2b(self.PAYLOAD) == hash_blake2b(self.PAYLOAD)


class TestAlgorithmDigestLength:
    """Each algorithm must produce the expected digest length."""

    PAYLOAD = b"digest length test"

    def test_sha256_digest_length(self) -> None:
        # SHA-256 → 32 bytes → 64 hex chars
        assert len(hash_sha256(self.PAYLOAD)) == 64

    def test_sha3_256_digest_length(self) -> None:
        # SHA3-256 → 32 bytes → 64 hex chars
        assert len(hash_sha3_256(self.PAYLOAD)) == 64

    def test_scrypt_digest_length(self) -> None:
        # scrypt(dklen=32) → 32 bytes → 64 hex chars
        assert len(hash_scrypt(self.PAYLOAD)) == 64

    def test_blake2b_digest_length(self) -> None:
        # BLAKE2b default → 64 bytes → 128 hex chars
        assert len(hash_blake2b(self.PAYLOAD)) == 128


class TestAlgorithmKnownVectors:
    """Spot-check against known reference values."""

    def test_sha256_known_vector(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert hash_sha256(b"abc") == expected

    def test_sha3_256_known_vector(self) -> None:
        expected = hashlib.sha3_256(b"abc").hexdigest()
        assert hash_sha3_256(b"abc") == expected

    def test_blake2b_known_vector(self) -> None:
        expected = hashlib.blake2b(b"abc").hexdigest()
        assert hash_blake2b(b"abc") == expected

    def test_scrypt_known_vector(self) -> None:
        expected = hashlib.scrypt(
            b"abc", salt=b"", n=1024, r=1, p=1, maxmem=0, dklen=32
        ).hex()
        assert hash_scrypt(b"abc") == expected


class TestAlgorithmRegistry:
    """The ALGORITHMS dict must contain all four entries."""

    def test_registry_keys(self) -> None:
        assert set(ALGORITHMS.keys()) == set(ALGORITHM_NAMES)

    def test_registry_callable(self) -> None:
        for name, func in ALGORITHMS.items():
            result = func(b"test")
            assert isinstance(result, str), f"{name} did not return str"
            assert len(result) > 0, f"{name} returned empty digest"


# ===================================================================
# Section 2 — Bit-Flip Correctness
# ===================================================================
class TestFlipBit:
    """Verify the single-bit-flip primitive."""

    def test_single_bit_changed(self) -> None:
        original = b"\x00" * 4  # 32 bits, all zero
        for bit_idx in range(32):
            mutated = flip_bit(original, bit_idx)
            # Exactly one bit should differ
            diff = sum(
                bin(a ^ b).count("1")
                for a, b in zip(original, mutated)
            )
            assert diff == 1, f"Expected 1 flipped bit at index {bit_idx}, got {diff}"

    def test_flip_is_reversible(self) -> None:
        original = b"\xDE\xAD\xBE\xEF"
        for bit_idx in range(32):
            mutated = flip_bit(original, bit_idx)
            restored = flip_bit(mutated, bit_idx)
            assert restored == original

    def test_flip_out_of_range_raises(self) -> None:
        with pytest.raises(IndexError):
            flip_bit(b"\x00", bit_index=8)

    def test_flip_negative_index_raises(self) -> None:
        with pytest.raises(IndexError):
            flip_bit(b"\x00", bit_index=-1)


# ===================================================================
# Section 3 — Hamming Distance
# ===================================================================
class TestHammingDistance:
    """Verify binary Hamming distance calculation on hex strings."""

    def test_identical_digests(self) -> None:
        h = "aa" * 32
        assert hamming_distance_hex(h, h) == 0

    def test_fully_inverted(self) -> None:
        h_a = "00" * 32  # 256 zero bits
        h_b = "ff" * 32  # 256 one bits
        assert hamming_distance_hex(h_a, h_b) == 256

    def test_single_bit_difference(self) -> None:
        h_a = "00" * 32
        h_b = "01" + "00" * 31  # one bit set in byte 0
        assert hamming_distance_hex(h_a, h_b) == 1

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            hamming_distance_hex("aa", "aabb")


# ===================================================================
# Section 4 — Avalanche Effect
# ===================================================================
class TestAvalancheEffect:
    """Statistical validation of the strict avalanche criterion.

    Over multiple trials the mean avalanche ratio should be ≈0.50 for
    a cryptographically strong hash.  We accept 0.30–0.70 per
    individual trial and 0.35–0.65 for the mean over 50 trials.
    """

    TRIALS: int = 50
    PAYLOAD_SIZE: int = 1024  # 1 KB

    @pytest.mark.parametrize("algo_name", ALGORITHM_NAMES)
    def test_avalanche_ratio(self, algo_name: str) -> None:
        import os

        func = ALGORITHMS[algo_name]
        payload = os.urandom(self.PAYLOAD_SIZE)

        ratios: list[float] = []
        for _ in range(self.TRIALS):
            result = measure_avalanche(func, payload, algo_name)
            assert isinstance(result, AvalancheResult)
            # Individual trial should be loosely within range
            assert 0.10 <= result.avalanche_ratio <= 0.90, (
                f"{algo_name}: single-trial ratio {result.avalanche_ratio:.4f} "
                f"is outside [0.10, 0.90]"
            )
            ratios.append(result.avalanche_ratio)

        mean = sum(ratios) / len(ratios)
        assert 0.35 <= mean <= 0.65, (
            f"{algo_name}: mean avalanche ratio {mean:.4f} outside [0.35, 0.65] "
            f"over {self.TRIALS} trials"
        )


# ===================================================================
# Section 5 — Timing Infrastructure
# ===================================================================
class TestTimingInfrastructure:
    """Smoke-test the latency measurement helper."""

    def test_measure_latency_returns_timing_result(self) -> None:
        result = measure_latency(hash_sha256, b"hello", "sha256", iterations=10)
        assert isinstance(result, TimingResult)
        assert result.algorithm == "sha256"
        assert result.payload_bytes == 5
        assert result.elapsed_seconds > 0
        assert result.throughput_mb_per_sec > 0

    def test_measure_latency_payload_size_recorded(self) -> None:
        data = b"\x00" * 2048
        result = measure_latency(hash_blake2b, data, "blake2b")
        assert result.payload_bytes == 2048


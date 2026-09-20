# CipherChain — Cryptographic Benchmark Test Harness

## 1. Overview

**CipherChain** is a rigorous, purely analytical cryptographic test harness engineered to benchmark the architectural and performance trade-offs of structurally distinct hash functions and key derivation algorithms. Built from the ground up for academic research, the framework empirically evaluates four target algorithms across three core cryptographic properties:

1. **Throughput & Latency:** Raw processing bandwidth ($\text{MB/s}$) and per-operation latency across dynamically scaled payloads ($1\text{ KB}$ to $100\text{ MB}$).
2. **Memory Footprint & Hardness:** Real-time process Resident Set Size ($\text{RSS}$) tracking to contrast in-register streaming digests against Scrypt's memory-hard scratchpad ($128 \cdot r \cdot N\text{ bytes}$).
3. **Avalanche Effect (Strict Avalanche Criterion - SAC):** Bit-level Hamming distance analysis over independent single-bit input perturbation trials to verify $\approx 50\%$ output diffusion.

Data processing and aggregations are powered by **Polars**, and figures are exported at $300\text{ DPI}$ IEEE publication quality.

---

## 2. Target Algorithms & Architectural Taxonomy

| Algorithm | Construction / Architecture | Digest Size | Primary Design Goal |
|---|---|---:|---|
| **SHA-256** | Merkle-Damgård (compression function) | $256\text{ bits}$ | NIST standard; ubiquitous integrity verification; hardware-accelerated (SHA-NI). |
| **SHA3-256** | Sponge Construction (Keccak-$p[1600, 24]$) | $256\text{ bits}$ | Permutation-based; immune to length-extension attacks; cryptographic hedge. |
| **Scrypt** | Sequential Memory-Hard PBKDF | $256\text{ bits}$ (configurable) | ASIC/GPU resistance via deliberate memory and cache-line hardness. |
| **BLAKE2b** | ARX (Addition-Rotation-XOR) | $512\text{ bits}$ | High-performance software hashing optimized for 64-bit architectures. |

---

## 3. Experimental Metrics

### 3.1 Throughput & Latency
- Measured using monotonic high-resolution timers (`time.perf_counter`).
- Dynamic payload scaling: $1\text{ KB}$, $10\text{ KB}$, $100\text{ KB}$, $1\text{ MB}$, $10\text{ MB}$, and $100\text{ MB}$.
- Iterations are auto-tuned to amortize timer granularity.
- Scrypt is evaluated under its standard role as a parameter-dominated KDF; its payload is bounded to $1\text{ MB}$ to isolate cost-parameter execution.

### 3.2 Memory Profiling & Hardness
- Samples process RSS before, during, and after execution via `memory_profiler`.
- Validates Scrypt memory allocation against Colin Percival's theoretical model:
  $$\text{Memory} = 128 \times r \times N\text{ bytes}$$
- Evaluates both baseline ($N=1024, r=1 \approx 128\text{ KiB}$) and scaled configurations:
  - $N=16384, r=8, p=1 \implies \approx 16\text{ MiB}$ RAM
  - $N=32768, r=8, p=1 \implies \approx 32\text{ MiB}$ RAM

### 3.3 Strict Avalanche Criterion (SAC)
- Implements an exact single-bit flip operator (MSB-first ordering).
- Compares original and mutated outputs using binary XOR Hamming distance:
  $$\text{Avalanche Ratio} = \frac{\text{HammingDistance}(H(m), H(m \oplus e_i))}{\text{Total Digest Bits}}$$
- Validates that the mean bit-variance over 20 independent trials per payload size satisfies $0.50 \pm 0.05$.

---

## 4. Repository Structure

```
cipher-chain/
├── pyproject.toml              # Project metadata & uv dependencies
├── uv.lock                     # Deterministic dependency lockfile
├── README.md                   # Academic landing page
├── src/
│   ├── __init__.py             # Core package initialization
│   ├── algorithms.py           # Native hashlib wrappers (SHA-256, SHA3-256, Scrypt, BLAKE2b)
│   ├── metrics.py              # High-resolution timing & RSS memory tracking
│   └── avalanche.py            # Single-bit mutation & Hamming distance engine
├── benchmarks/
│   ├── __init__.py
│   ├── run_throughput.py       # CLI throughput harness -> data/throughput.csv
│   ├── run_memory.py           # CLI memory & hardness harness -> data/memory.csv
│   └── run_avalanche.py        # CLI SAC avalanche harness -> data/avalanche.csv
├── notebooks/
│   └── hashing_analysis.ipynb  # Interactive Polars analytics & visualization pipeline
├── figures/                    # Publication-grade figures (300 DPI PNG)
│   ├── throughput_vs_payload.png
│   ├── memory_consumption.png
│   └── avalanche_distribution.png
├── tests/
│   ├── __init__.py
│   └── test_crypto.py          # Pytest validation suite (28 test cases)
└── data/                       # Experimental CSV datasets (auto-generated)
```

---

## 5. Quickstart Guide (`uv`)

This project standardizes all environment and package management using [**uv**](https://docs.astral.sh/uv/), Astral's extremely fast Python package manager.

### 5.1 Prerequisites & Installation

Install `uv` (if not already present):

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via pip
pip install uv
```

Clone the repository and install all locked dependencies:

```bash
git clone https://github.com/IamShauryaSuman/cipher-chain.git
cd cipher-chain

# Synchronize virtual environment
uv sync
```

### 5.2 Running the Cryptographic Verification Suite

Verify algorithm determinism, known test vectors, bit-flip reversibility, Hamming distance, and avalanche statistical bounds:

```bash
uv run pytest -v
```

### 5.3 Executing Benchmarks

Run the standalone CLI benchmarking scripts. Results will automatically write to structured CSV files in the `data/` directory:

```bash
# 1. Throughput & Latency Benchmark (1 KB -> 100 MB)
uv run python -m benchmarks.run_throughput

# 2. Memory Footprint & Hardness Profiling (including N=16384 & N=32768 Scrypt)
uv run python -m benchmarks.run_memory

# 3. Avalanche Effect SAC Testing (20 random-bit trials per configuration)
uv run python -m benchmarks.run_avalanche
```

### 5.4 Launching the Analysis Notebook

To ingest the benchmark results, compute Polars aggregations, and generate the $300\text{ DPI}$ figures:

```bash
uv run jupyter lab
```

Open `notebooks/hashing_analysis.ipynb` and execute all cells. The notebook automatically updates:
- `data/hashing_summary.csv`
- `figures/throughput_vs_payload.png`
- `figures/memory_consumption.png`
- `figures/avalanche_distribution.png`

Headless execution via CLI:

```bash
uv run jupyter nbconvert --to notebook --execute notebooks/hashing_analysis.ipynb --output hashing_analysis.ipynb
```

---

## 6. Academic Citation & Context

Developed as part of the coursework for:

```text
BITS F463: Cryptography
Department of Computer Science & Information Systems
Birla Institute of Technology and Science, Pilani — K.K. Birla Goa Campus
Academic Year: 2026–2027
```
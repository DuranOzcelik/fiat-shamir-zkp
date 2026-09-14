# Fiat-Shamir Zero-Knowledge Identification Protocol

A complete Python implementation and experimental analysis of the **Fiat-Shamir zero-knowledge identification protocol**, with an interactive **Streamlit web interface** for stepping through the protocol and running the security test suite in the browser.

Developed as a course project for *BIM474 – Introduction to Cryptography* (Eskisehir Technical University, Department of Computer Engineering).

📊 Presentation slides: [`docs/Fiat_Shamir_ZKP_Presentation.pptx`](docs/Fiat_Shamir_ZKP_Presentation.pptx)

---

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Protocol Description](#protocol-description)
4. [Project Structure](#project-structure)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Security & Performance Evaluation](#security--performance-evaluation)
8. [Implementation Notes](#implementation-notes)
9. [Limitations & Future Work](#limitations--future-work)
10. [References](#references)
11. [Disclaimer](#disclaimer)

---

## Overview

The Fiat-Shamir scheme allows a **prover** to convince a **verifier** that it knows a secret value `s` without revealing any information about `s` itself. This project:

- implements the full protocol in Python using cryptographically secure randomness (`secrets` module) and large-integer arithmetic (`sympy` for prime generation);
- experimentally verifies the three defining properties of a zero-knowledge proof system — **completeness**, **soundness** and **zero-knowledge** — through a dedicated `SecurityAnalyzer`;
- provides an interactive Streamlit application for step-by-step visualisation of the protocol, intended for educational use.

---

## Background

### Zero-knowledge proof systems

Goldwasser, Micali and Rackoff (1985) formalised zero-knowledge proofs and the three properties every ZKP system must satisfy:

| Property | Meaning |
|---|---|
| **Completeness** | An honest prover with the correct witness convinces an honest verifier with overwhelming probability. |
| **Soundness** | A cheating prover without the witness cannot convince the verifier except with negligible probability (the *soundness error*). |
| **Zero-knowledge** | The verifier learns nothing beyond the fact that the statement is true. Formally, a polynomial-time *simulator* exists that produces transcripts indistinguishable from real executions without access to the witness. |

### Quadratic residuosity

The security of the Fiat-Shamir scheme rests on the **quadratic residuosity assumption**: given a composite modulus `n = p·q` with unknown factorisation, computing square roots modulo `n` is as hard as factoring `n`. The arithmetic requires only modular squarings and multiplications, which makes the protocol efficient and easy to reason about.

---

## Protocol Description

**Key generation**

1. Choose two large primes `p` and `q` and compute `n = p·q`.
2. Choose a secret `s` with `gcd(s, n) = 1` and `1 < s < n`.
3. Publish the public key `v = s² mod n`; keep `s` (and `p`, `q`) secret.

**One round of identification**

| Step | Party | Message |
|---|---|---|
| 1 | Prover → Verifier | pick random `r`, send commitment `x = r² mod n` |
| 2 | Verifier → Prover | send random challenge bit `e ∈ {0, 1}` |
| 3 | Prover → Verifier | send response `y = r · sᵉ mod n` |
| 4 | Verifier | accept the round iff `y² ≡ x · vᵉ (mod n)` |

**Correctness.** For an honest prover, `y² = r² · s^(2e) = x · vᵉ (mod n)`, so the check always passes.

**Soundness.** A prover who does not know `s` can prepare a valid answer for only one of the two possible challenges in advance. Hence the probability of cheating in one round is `1/2`, and after `t` independent rounds it is `(1/2)ᵗ` — below one-in-a-million at `t = 20`.

**Zero-knowledge.** A simulator can generate valid-looking transcripts *backwards*: choose `e` and `y` first, then set `x = y² · v⁻ᵉ mod n`. The resulting `(x, e, y)` passes verification and is distributed identically to a real transcript, yet was produced without `s`.

---

## Project Structure

```
fiat-shamir-zkp/
├── config.py        — protocol constants and defaults (key sizes, round bounds, test counts)
├── keygen.py        — RSA-like key-pair generation (p, q, n, s, v)
├── prover.py        — honest Prover and DishonestProver classes
├── verifier.py      — challenge issuance and verification logic
├── simulator.py     — ZKSimulator: zero-knowledge transcript simulator
├── protocol.py      — FiatShamirProtocol: the t-round orchestrator
├── analysis.py      — SecurityAnalyzer: completeness, soundness, ZK and performance tests
├── app.py           — Streamlit web interface
├── main.py          — command-line entry point
├── requirements.txt
└── docs/
    └── Fiat_Shamir_ZKP_Presentation.pptx
```

Modules communicate only through typed dataclasses (`Commitment`, `Challenge`, `Response`, `Transcript`, `RoundResult`, `ProtocolResult`), which strictly enforces the protocol's communication model — the prover and verifier never share internal state.

---

## Installation

Python 3.11 or later is recommended.

```bash
git clone https://github.com/DuranOzcelik/fiat-shamir-zkp.git
cd fiat-shamir-zkp
pip install -r requirements.txt
```

No datasets, pre-generated keys or fixed seeds are needed — everything is generated at runtime.

> **Windows note:** the CLI prints Unicode symbols (`ᵉ`, `≡`, `✓`). If your console uses a legacy code page, run `set PYTHONIOENCODING=utf-8` (cmd) or `$env:PYTHONIOENCODING="utf-8"` (PowerShell) first.

---

## Usage

### Command line

All commands go through `main.py`. The optional global flag `--key-size` accepts 256, 512, 1024 or 2048 bits (default 512) and must be given *before* the subcommand. Round counts must be between 10 and 100.

```bash
# Single protocol session with an honest prover (20 rounds)
python main.py run

# Watch a dishonest prover get caught
python main.py run --dishonest

# Custom key size and number of rounds
python main.py --key-size 1024 run --rounds 30

# Completeness test: 100 honest runs, checks the acceptance rate
python main.py completeness

# Soundness test: dishonest prover attempts across several round counts
python main.py soundness --attempts 200

# Zero-knowledge test: real vs. simulated transcripts
python main.py zk --count 100

# Performance benchmark: key generation and per-round timing across key sizes
python main.py performance --rounds 20 --trials 10
```

### Web interface

```bash
streamlit run app.py
```

Open `http://localhost:8501`. The interface lets you:

- generate keys and step through the protocol round by round, with every `x`, `e`, `y` value shown;
- switch between an **honest** and a **dishonest** prover in the sidebar;
- run the **Completeness**, **Soundness** and **Zero-knowledge** tests with one click and inspect the results as charts and colour-coded tables;
- run the performance benchmark across key sizes.

The three security-test tabs respect the prover type selected in the sidebar, so you can observe how completeness breaks down and how per-round transcript validity drops to ~50 % when the prover does not know the secret.

---

## Security & Performance Evaluation

All experiments use randomness from the OS CSPRNG via Python's `secrets` module (no fixed seed). Timings were measured with `time.perf_counter` on an Intel Core i5 (11th gen, 2.4 GHz) laptop with 8 GB RAM running Python 3.11.

### Completeness — honest protocol, `t = 20` rounds

| Key size (bits) | Runs | Accepted | Rate |
|---|---|---|---|
| 256  | 100 | 100 | 100.0 % |
| 512  | 100 | 100 | 100.0 % |
| 1024 | 100 | 100 | 100.0 % |

Perfect completeness across all 300 honest executions, as predicted by the correctness identity.

### Soundness — single round (10 000 trials, 512-bit key)

| Theoretical | Observed | Deviation |
|---|---|---|
| 50.000 % | 49.97 % | −0.03 % |

### Soundness — cheating success rate vs. rounds (1 000 attempts, 512-bit key)

| Rounds `t` | Theoretical `2⁻ᵗ` | Observed | Verdict |
|---|---|---|---|
| 5  | 3.125 %  | 3.18 % | Sound ✓ |
| 10 | 0.098 %  | 0.10 % | Sound ✓ |
| 15 | 0.003 %  | 0.00 % | Sound ✓ |
| 20 | < 10⁻⁶   | 0.00 % | Sound ✓ |

Observed cheating rates match the `(1/2)ᵗ` bound within statistical error; the soundness error is operationally zero from `t = 15` onward.

### Zero-knowledge — real vs. simulated transcripts (512-bit key)

| Source | Count | Valid | Rate |
|---|---|---|---|
| Real (with secret `s`) | 100 | 100 | 100.0 % |
| Simulated (no secret)  | 100 | 100 | 100.0 % |

The simulator produces transcripts that pass verification without any knowledge of `s`. The challenge-bit distribution in both groups was uniform (`e = 0` ≈ 50 %, `e = 1` ≈ 50 %), confirming no bias leakage.

### Performance — `t = 20` rounds, averaged over 50 trials

| Key size (bits) | Key generation (ms) | Per round (ms) | 20-round total (ms) |
|---|---|---|---|
| 256  | 34.2  | 0.09 | 1.8  |
| 512  | 98.7  | 0.31 | 6.2  |
| 1024 | 412.5 | 1.19 | 23.8 |

Key generation (Miller-Rabin primality testing over large candidates) dominates. Per-round time scales roughly quadratically with the key size, as expected for schoolbook modular multiplication. 2048-bit keys are supported but not benchmarked; key generation at that size can take several seconds.

---

## Implementation Notes

- **Secure randomness.** All random values (`p`, `q`, `s`, `r`, `e`) are drawn from `secrets`; the `random` module is never used.
- **Safe secret generation.** `keygen.py` requires `gcd(s, n) = 1`, `1 < s < n` and `s² > n`, so that `v = s² mod n` is a genuine modular reduction and does not leak the bit length of `s`.
- **DishonestProver.** Always answers `y = r` regardless of `e`. This passes only when `e = 0`, i.e. about half the time per round — exactly the random-guess strategy the soundness bound models.
- **ZKSimulator.** Picks `y` and `e` first, then computes `x = y² · v⁻ᵉ mod n` using the precomputed modular inverse of `v`. The transcript is guaranteed to verify without ever touching `s`.
- **SecurityAnalyzer** (`analysis.py`) exposes `test_completeness`, `test_soundness`, `test_zero_knowledge`, `test_performance` and a single-round cheating-probability estimator. The first three accept an optional `prover_type` argument so the same tests can be run against an honest or a dishonest prover.

---

## Limitations & Future Work

- To reach a 128-bit security level the scheme needs a ~3072-bit modulus, whereas Schnorr over Curve25519 needs only a 256-bit scalar.
- The binary challenge space limits the per-round soundness error to `1/2`. The **parallel Fiat-Shamir** variant with `k` independent secrets reduces this to `2⁻ᵏ` per round at the cost of larger messages.
- Possible extensions: implement the parallel variant, apply the **Fiat-Shamir transform** to obtain a non-interactive signature scheme, and benchmark against Schnorr using the `cryptography` library.

---

## References

1. A. Fiat and A. Shamir, "How to Prove Yourself: Practical Solutions to Identification and Signature Problems," *CRYPTO '86*, 1987.
2. S. Goldwasser, S. Micali and C. Rackoff, "The Knowledge Complexity of Interactive Proof Systems," *SIAM Journal on Computing*, 18(1), 1989.
3. C. P. Schnorr, "Efficient Signature Generation by Smart Cards," *Journal of Cryptology*, 4(3), 1991.

---

## Disclaimer

This implementation is intended solely for **educational and research purposes**. It is not a production-grade cryptographic library and has not been audited; do not use it to protect real systems.

## Author

**Duran Ozcelik** — [github.com/DuranOzcelik](https://github.com/DuranOzcelik)

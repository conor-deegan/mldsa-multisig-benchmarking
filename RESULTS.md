# Results

Execute-mode cycle counts for a 6-of-10 ML-DSA-65 proof inside SP1. All three configurations verified successfully in the zkVM (`all valid: true`). Cycles are the portable, host-independent metric.

| # | Hash backend | Precompile | Total cycles | Cycles / signature | Precompile syscalls |
|--:|--------------|------------|-------------:|-------------------:|---------------------|
| 1 | `shake` (ml-dsa default) | none   | 19865152 | 3310858 | — |
| 2 | `sha3`                   | none   | 21793956 | 3632326 | — |
| 3 | `sha3`                   | Keccak | 13611496 | 2268582 | `KECCAK_PERMUTE` × 1248 |

## Opcode breakdown (config 3: `sha3` + Keccak precompile)

Host-side opcode histogram of the same execute run as config 3 (13611496 RISC-V instructions; keccak-f runs as a syscall and is counted above, not here).

### By category

| Category | Instructions | Share |
|----------|-------------:|------:|
| multiply (`MUL*`)                  |  748521 |  5.5% |
| divide / remainder (`DIV*`/`REM*`) |       0 |  0.0% |
| memory load                        | 1947011 | 14.3% |
| memory store                       | 1684690 | 12.4% |
| branch / jump                      | 1291178 |  9.5% |
| other (ALU / imm / system)         | 7940096 | 58.3% |

### Top 12 opcodes

| Opcode | Instructions | Share |
|--------|-------------:|------:|
| `ADDI` | 2634219 | 19.4% |
| `SD`   | 1094130 |  8.0% |
| `LD`   | 1020897 |  7.5% |
| `ADD`  |  950479 |  7.0% |
| `AND`  |  891460 |  6.5% |
| `SLL`  |  717926 |  5.3% |
| `SLTU` |  621837 |  4.6% |
| `OR`   |  547689 |  4.0% |
| `MUL`  |  523387 |  3.8% |
| `BNE`  |  451375 |  3.3% |
| `SW`   |  433086 |  3.2% |
| `ADDW` |  420840 |  3.1% |

## Proof size and time

Indicative only — proving time, verify time, and proof size are MacBook-relative, not deployable costs. All runs use `sha3` + the Keccak precompile in **core** mode (compression/Groth16 OFF).

### Device specs

```
=== System ===           === CPU ===            === Memory ===
OS:    macOS 26.4.1       Apple M5               32 GB
Kernel: 25.4.0            Cores:   10
Arch:  arm64              Threads: 10

=== Rust ===
rustc 1.94.1 (e408947bf 2026-03-25)
cargo 1.94.1 (29ea6fb6a 2026-03-24)
```

### Measurements (1-of-1 → 3-of-3)

| Config | Total cycles | Cycles / sig | `KECCAK_PERMUTE` | Prove time | Verify time | Proof size |
|--------|-------------:|-------------:|-----------------:|-----------:|------------:|-----------:|
| 1-of-1 | 2278653 | 2278653 | 208 | 31.44 s | 86.28 ms | 4284551 B |
| 2-of-2 | 4546823 | 2273411 | 416 | 46.61 s | 86.53 ms | 4316639 B |
| 3-of-3 | 6811099 | 2270366 | 624 | 66.68 s | 90.79 ms | 4347999 B |

### How each metric scales

Marginal cost of adding one signature, and a least-squares fit over the three points (`n` = number of signatures verified):

| Metric | Δ per sig (1→2) | Δ per sig (2→3) | Shape | Fit (`n` = sigs) | R² |
|--------|----------------:|----------------:|-------|------------------|---:|
| Total cycles      | +2,268,170 | +2,264,276 | linear, ~zero intercept | ≈ **2.266M·n** + 13k | 1.0000 |
| `KECCAK_PERMUTE`  | +208       | +208       | exactly linear          | = **208·n**          | 1.0000 |
| Prove time        | +15.17 s   | +20.07 s   | ~linear + fixed base    | ≈ **17.6·n + 13** s  | 0.9936 |
| Verify time       | +0.25 ms   | +4.26 ms   | ~constant               | ≈ **83 + 2.3·n** ms  | 0.7914 |
| Proof size        | +32,088 B  | +31,360 B  | linear on a huge base   | ≈ **31.7 KB·n + 4.25 MB** | 1.0000 |

My interpretation: 

1. **In-zkVM work scales linearly with N, with no shared cost.** Cycles and `KECCAK_PERMUTE` are dead-straight lines through the origin: every signature is verified independently, so there is nothing to amortise across signers. Cycles/sig is essentially flat (~2.27M) and drifts *down* only because the tiny ~13k fixed overhead gets spread over more signatures. Keccak is exactly **208 permutations per signature**.
2. **The proof artifact is dominated by fixed overhead.** Proof size grows <1% per signature on a ~4.25 MB base, and verify time stays ~86–91 ms regardless of N. Thus **adding signers barely changes the proof you ship or the time to verify it** - the cost lives entirely in proving.
3. **Prove time** sits between the two: roughly linear at ~17.6 s/sig with a ~13 s fixed cost, but it is the least reliable line here (R²=0.99, yet the marginal jumped 15.2 → 20.1 s). It is MacBook-relative and SP1 batches cycles into power-of-two shards, so it's expected for to move in steps - not a smooth slope - and thermal throttling on longer runs likely explains the upward drift. Treat the cycle/keccak/size fits as solid and the prove-time slope as indicative.

**Extrapolation cross-check.** The cycle model fit on `n = 1, 2, 3` predicts **n = 6** at 2.266M·6 + 13k ≈ **13,610,417** cycles. The independently measured **6-of-10** run (top of this file) was **13,611,496** — an error of **0.008%**. So the linear model extrapolates cleanly: for an N-of-M policy on this machine, expect roughly

- cycles ≈ **2.27M · N**
- keccak perms = **208 · N**
- proof size ≈ **4.25 MB + 31.7 KB · N**
- verify ≈ **~90 ms** (≈ constant)
- prove ≈ **13 s + 17.6 s · N** (rough; M5, core mode)

## My thesis on the precompiles

**Numbers:** Swapping `shake` → `sha3` on its own made things *worse* (19.87M → 21.79M cycles, +9.7%): which makes sense as any expected win is going to be from the precompile, not the dependency change. With the Keccak precompile the 1248 `KECCAK_PERMUTE` permutations become syscalls and total cycles drop to 13.61M (−31.5%) vs the original `shake` baseline.

**My read of the next bottleneck:** After the precompile, multiply is only 5.5% and divide/remainder is 0% so the NTT/modular-arithmetic is *not* where bottleneck is (I think?). It looks like the remianing bottlenecks are glue ops like bit packing and moving coefficients around. No single hot primitive is left AFAICT.

**Implication for precompiles:** There's nothing left worth precompiling I think. None of SP1's
other stock precompiles (SHA-256, the elliptic curves, 256-bit bigint) map onto ML-DSA,
and even a bespoke NTT/modmul precompile would impact ≤5.5%.

## GPU testing

Config:
- 1x A10
- 24GB VRAM/GPU
- 30 vCPUs
- 226  GiB  RAM
- 1.3 TiB SSD
- $1.29 GPU/HR
- Image: Lambda Stack 24.04

### M5 (CPU) vs A10 (CUDA) — 6-of-10, core mode

Same binary, same statement, same inputs. Only the prover backend differs (`SP1_PROVER=cuda`).

| Metric | M5 (CPU) | A10 (CUDA) | Delta |
|--------|---------:|-----------:|-------|
| Total cycles | 13611496 | 13611496 | identical (portable) |
| Prove time   | 119.95 s | 5.70 s    | **~21× faster** |
| Verify time  | 116.37 ms | 462.12 ms | ~4× slower |
| Proof size   | 5893025 B | 7341627 B | +24.6% |

**Reasoning:**

1. **Cycles are identical** - execute is deterministic and host-independent, so the GPU is a drop-in prover doing the exact same work.
2. **Prove time ~21× faster** is the whole point of the GPU, and the only metric it targets.
3. **Bigger proof + slower verify are not a regression.** Cycle counts match, so it isn't extra work, the CUDA prover just shards differently and emits a larger proof. Verify runs CPU-side (on this box's vCPUs, weaker per-core than the M5) and scales with proof structure, so a +25% proof verifies ~4× slower. If needed a small, fast-to-verify proof is needed we could look at compression/Groth16 wrapping and not core mode but this may impact PQ-ness.

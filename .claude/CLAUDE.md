# Project: add a Binius64 prover to mldsa-multisig-benchmarking

You are adding a `binius-prover` crate that proves the SAME N-of-M ML-DSA-65
statement the `sp1-prover` and `default-verifier` crates already handle, but as a
hand-written Binius64 circuit. Binius64 is NOT a zkVM — you build a circuit with
`binius_frontend::CircuitBuilder` and gadgets from `binius_circuits`. Read SPEC.md
first, every session.

## Non-negotiable invariants (the Stop hook and circuit-adversary enforce these)
- The `ml-dsa` crate is read-only ground truth. Never modify it; never call it at
  circuit runtime to decide acceptance. It exists only to generate test vectors and
  as the reference inside `default_verifier::verify_all`.
- `binius-prover/tests/xcheck.rs` is the success oracle. Never weaken it, never flip
  an `expect_accept`/`expect_reject`, never special-case, skip, or allowlist a vector
  to make it pass. A red oracle means the circuit is wrong, not the test.
- No hardcoded witnesses, no toy stubs passed off as real. If something is a
  placeholder, mark it `// TODO(stub):` and do not claim the oracle passes. Flag
  uncertainty rather than confabulate a passing result.
- Every nondeterministic (witness) value that feeds an arithmetic relation must be
  pinned by a constraint. Range-check every mod-q remainder. This is the difference
  between a sound circuit and a worthless one.
- You sequence the work yourself (suggested order in SPEC.md §7). Do one focused
  increment per run; the repo + NOTES.md are your memory across runs. Commit working
  increments on the `binius-prover` branch. Never work on `main`.
- Build and test with `RUSTFLAGS="-C target-cpu=native"`.
- British English in all comments, docs, and RESULTS.md prose.

## References
- Binius64: docs.binius.xyz, binius.xyz/building, repo IrreducibleOSS/binius64.
  The `ethsign` example (ECDSA aggregation) is the closest pattern — signature
  verification inside a circuit. Read it before writing M4.
- FIPS 204 for the ML-DSA-65 verify algorithm. Mirror the reference's checks exactly.

## Workflow per run
1. Read SPEC.md, NOTES.md, and the current code. 2. Do one focused increment toward
the next thing in the suggested order. 3. Run the oracle
(`cargo test -p binius-prover --test xcheck`). 4. If you added constraints, optionally
invoke the `circuit-adversary` subagent and fix what it finds. 5. Append a one-line
status to NOTES.md and stop; the outer loop reruns the oracle and continues.

# Loop task — Binius64 ML-DSA-65 N-of-M prover

You are working autonomously on the `binius-prover` branch of
mldsa-multisig-benchmarking, adding a `binius-prover` crate that proves the same
N-of-M ML-DSA-65 statement as `sp1-prover`, but as a hand-written Binius64 circuit
(not a zkVM). Read SPEC.md and CLAUDE.md now, plus NOTES.md if it exists.

You get a fresh context each run, so the repository IS your memory: read the current
code and NOTES.md to see where things stand, then do ONE focused increment that
moves the oracle closer to green. Suggested order (sequence it yourself, adjust as
needed): mod-q gadgets → R_q polynomial mult → SHAKE/keccak + decode → single-sig
verify → N-of-M aggregation → end-to-end prove+verify + RESULTS.md.

The oracle is the only definition of done:
`RUSTFLAGS=-Ctarget-cpu=native cargo test -p binius-prover --test xcheck`
It checks soundness (corrupted inputs MUST be rejected), differential agreement with
the RustCrypto reference, and a proof round-trip. Make it pass for real.

Hard rules: never edit the `ml-dsa` reference or tests/xcheck.rs (both are
write-protected anyway); range-check every nondeterministic mod-q remainder; no
stubs passed off as done; British English. If SPEC.md is wrong or underspecified,
STOP and write the contradiction into SPEC.md as an open question rather than
improvising the cryptography. If this increment added constraints, you may invoke
the `circuit-adversary` subagent to red-team before finishing.

End your run by appending one line to NOTES.md: what you changed and the current
oracle status. Then stop — the outer loop reruns the oracle and starts the next
increment.

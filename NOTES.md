# NOTES — binius-prover loop log

One line per increment: what changed + current oracle status. Newest at the bottom.

- Pre-M0: added binius64 as a pinned git dep (binius-frontend/circuits/core @
  binius-zk/binius64 rev 8f21b34) in new `binius-prover/Cargo.toml` + empty
  `src/lib.rs` stub; added crate to workspace members; `cargo build -p binius-prover
  --lib` green, dep locked. Filled every SPEC.md blank (§2 mod-q gadgets: single-word
  imul + divmod-hint + icmp_ult range-check, no bignum; §2 NTT over schoolbook with
  count justification; §2 one coeff/word packing + t1/z/c̃/h/w1 decode; §3 SHAKE built
  on keccak_f1600 with 0x1F pad — no SHAKE gadget exists; §3a ExpandA/SampleInBall
  fixed over-sampling; §4 mirror raw_verify_mu = c̃ equality only). Added §0a facts and
  §8 Corrections (no norm/weight checks, no key-distinctness in verify_all). No circuit
  code written. Oracle RED (expected): xcheck does not compile until M0 implements
  build/circuit_accepts/prove_and_verify/Case. Next: M0 scaffold + CLI.
- M0 scaffold: implemented the frozen xcheck contract. `policy::Policy` now derives
  Clone/Debug/Eq; `signing::sign` reshaped to `sign(&Policy,&[u8],&mut impl RngCore)
  -> Signed{keys(m),sigs(n)}` for the oracle, old fixed-seed behaviour preserved as
  `sign_default` (callers in default-verifier/demo/sp1-prover/benches updated). Added
  real `Case` (byte-level artifact) with parse() + all 6 corruption helpers; parse
  drops non-decodable sigs (= invalid). `build`/`circuit_accepts`/`prove_and_verify`/
  `ProofStats`/`CircuitError` + CLI (src/main.rs) in place; circuit_accepts is a
  marked TODO(stub) returning Unimplemented (no fake green). Moved policy/signing/
  ml-dsa/rand to lib deps (Case names their types). Toolchain installed (rust 1.96).
  Build green; default-verifier tests + demo build green. Oracle RED as designed:
  COMPLETENESS fails (stub rejects honest) + spurious DIFFERENTIAL on reference-accepts
  corruptions (unused-key flips / n<2 swaps — resolve at M4/M5, see SPEC §8.5). Added
  SPEC §8.5 (Signature::decode enforces ‖z‖∞/hint validity; M0–M3 oracle behaviour).
  Next: M1 mod-q gadgets (mul_mod_q/add_mod_q/sub_mod_q) with internal property tests.

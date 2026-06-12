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
- M1 mod-q gadgets: added `src/field.rs` (private `mod field`) with `FieldConsts`,
  `mul_mod_q` (imul + divmod-hint + in-circuit k·q+r==p with no-wrap carry check +
  r<q range-check), `reduce_mod_q` (lazy-reduction-capable, any p<2⁶⁴), `add_mod_q`
  /`sub_mod_q` (deterministic conditional subtract). 8 internal property tests green
  (2000 random + edge cases each, a negative output-coupling control, and a
  large-accumulator reduce test up to u64::MAX). circuit-adversary red-teamed it:
  caught that the original `k<q` range-check contradicted the documented multi-
  product lazy-reduction precondition (honest k>q for p>q² ⇒ completeness break);
  fixed by dropping k<q and instead asserting the iadd carry-out (cout MSB) is 0,
  which pins p=k·q+r over the integers for any p<2⁶⁴ while staying sound (kq_hi==0 +
  no-wrap + r<q uniquely force r=p mod q). Oracle still RED by design (circuit_accepts
  remains the M0 TODO(stub); M1 is internal gadgets only). Next: M2 R_q NTT.
- M2 R_q NTT: added `src/ntt.rs` (private `mod ntt`) — `zeta_pow_bitrev()` const
  twiddle table (ζ=1753, bitrev8, matches ml-dsa/ntt.rs Appendix B), `NttConsts`
  (256 fwd + 256 negated twiddle wires + 256⁻¹), forward `ntt` (8 CT layers 128→1,
  m:1..256), inverse `ntt_inverse` (8 GS layers + 256⁻¹ scale), `pointwise_mul`
  (MultiplyNTT). All butterflies compose the M1 field gadgets, so no new hints/
  nondeterminism beyond mul_mod_q's vetted remainder range-check. 5 property tests
  green: circuit-fwd/inverse vs an independent plain-Rust reference NTT, a wrong-
  output rejection, and the decisive multiplication-homomorphism anchor
  NTT⁻¹(NTT(f)∘NTT(g))==poly_mul(f,g) vs independent schoolbook negacyclic conv
  (a bad twiddle table cannot survive it). 13/13 lib tests pass. Oracle still RED by
  design (circuit_accepts remains the M0 TODO(stub); M2 is internal gadgets only).
  Next: M3 hashing (SHAKE128/256 on keccak_f1600) + byte↔coeff decode (t1/z/c̃/h/w1).

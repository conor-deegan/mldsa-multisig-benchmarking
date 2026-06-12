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
- M3a SHAKE: added `src/shake.rs` (private `mod shake`) — `shake128`/`shake256`
  XOFs built on upstream `Permutation::keccak_f1600` with the FIPS 202 `0x1F` pad
  (not the Keccak gadget's `0x01`). Shared `sponge(rate_words, in_len, out_len)`:
  pad10*1 (mirrors upstream keccak256's partial-word masking + `(len+1).div_ceil`
  block count, domain byte swapped to 0x1F), absorb by XOR into leading rate lanes,
  multi-block squeeze permuting between rate reads. All lengths compile-time known
  (no data-dependent loop). 8 bytes/word little-endian, matching upstream + sha3.
  No new hints/nondeterminism (keccak_f1600 is deterministic bit-ops). 4 property
  tests green vs the `sha3` crate (added as dev-dep): shake128/256 across rate- and
  word-boundary in/out lengths incl. the 840 B ExpandA squeeze and 48/64 B c̃/μ
  sizes, a wrong-output rejection, and a SHAKE128≠SHAKE256 separation. 17/17 lib
  tests pass. Oracle still RED by design (circuit_accepts is the M0 TODO(stub)).
  Next: M3b byte↔coeff decode (t1 Encode<10>, z BitUnpack<20>, c̃, h, w1 Encode<4>).
- M3b decode: added `src/decode.rs` (private `mod decode`) — the byte↔coefficient
  bridge. `extract_field` carves a compile-time-positioned `d`-bit little-endian
  field from the 8-bytes/word packed `inout` wires (constant `shr`/`shl`/`bor`/
  `band`, spanning ≤2 words since d≤20). `simple_bit_unpack(d)` → 256 coeff wires
  for t1 (d=10, mask pins [0,2¹⁰)<q canonical); `bit_unpack_gamma1` for z (d=20,
  centred value γ1−x via `sub_mod_q`, no ‖z‖∞ check per SPEC §4 — c̃ equality
  subsumes it); `simple_bit_pack(d=4)` re-encodes w1 → 16 words for the c̃′ absorb.
  All pure combinational (no hints/nondeterminism), so no new range-checks. 5
  property tests green: FIPS-204 Alg-16 known-answer (ml-dsa's own d=10 vector
  0,1..7), random t1 round-trips vs a plain-Rust reference decoder, wrong-output
  rejection, z centring vs (γ1−x) mod q over the full 20-bit range, and w1 encode
  vs reference at word granularity. 22/22 lib tests pass. Oracle still RED by
  design (circuit_accepts is the M0 TODO(stub); M3b is internal gadgets only).
  Next: M3c hint decode (h: ω-index + K-cut → K×256 hint bits, with bit_unpack
  validity constraints: cuts non-decreasing, max ≤ ω, post-cut zero, per-segment
  strictly increasing) — the last decode piece before M4 single-sig verify.

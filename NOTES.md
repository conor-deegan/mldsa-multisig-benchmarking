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
- M3c hint decode: added `decode_hint` to `src/decode.rs` — the in-circuit
  `Hint::bit_unpack` (FIPS-204 Alg-21 / `ml-dsa/src/hint.rs:128`). Carves the
  61-byte encoded hint (ω=55 index slots ∥ K=6 cumulative cut counts) from the
  packed `inout` words via `extract_byte`, then emits the four encoding-validity
  asserts that make the circuit unsatisfiable on any malformed hint the reference
  drops with `None`: (1) cuts non-decreasing (`icmp_ule` pairs); (2) max cut ≤ ω
  (max = cut[K-1] under rule 1); (3) index slots at/beyond max_cut forced zero
  (`assert_eq_cond` gated on `icmp_uge`); (4) per-segment strictly increasing,
  with the intra-segment pair predicate = (t+1 < max_cut) ∧ (t+1 not a cut value)
  — exactly the reference's per-segment `windows(2)` check since no cut can fall
  inside a segment interior. Output K×256 MSB-boolean wires via membership×eq OR;
  padding zeros (t≥max_cut) belong to no row so never reach the matrix. Per SPEC §2
  this is the sole home of the hint-weight ≤ ω bound. Pure combinational over the
  public hint bytes — no new hints/nondeterminism, so no new range-checks beyond
  the asserts. 4 new property tests green (known-answer, random round-trip, wrong-
  output rejection, all five malformed classes); circuit-adversary could not break
  it (2M+ biased-random + 135k exhaustive scaled model checks + circuit edge cases,
  verdict SOUND). 26/26 lib tests pass. Oracle still RED by design (circuit_accepts
  is the M0 TODO(stub); M3c is internal gadgets only). M3 decode complete (t1/z/c̃/
  h/w1). Next: M4 single-sig verify — SampleInBall + ExpandA rejection sampling
  (§3a fixed over-sampling) then the §4 verify chain wiring decode→NTT→UseHint→c̃′.
- M4 Decompose/UseHint: added `src/usehint.rs` (private `mod usehint`) — the §4
  step-7 high-bits gadget. `decompose` (FIPS-204 Alg-36) advises (q1,rem) for
  r=q1·2γ2+rem via `biguint_divide_hint`, pins the integer identity (qg_hi==0 +
  no-wrap carry + assert_eq) and range-checks rem<2γ2 — the sole new
  nondeterminism, fully forced (no q1 range-check needed: identity + reduced
  r<q ⇒ q1≤15). Centres r0 mod q, buckets r1∈[0,16), and detects the edge
  (diff==q-1 ⇔ r1_base==16, covering both upper-half-q1=15 and r=q-1-q1=16) wrapping
  r1→0 and r0-=1 via sub_mod_q (the 0→q-1 wrap at r=q-1). `use_hint` (Alg-40) takes
  an MSB-bool hint bit, does ±1 mod 16 via band-15 and the r0_positive=(r0≠0 &
  r0≤γ2) select. 6 property tests green vs an independent FIPS-204 reference
  (random + edge/boundary sweeps for both decompose and use_hint, wrong-output
  rejections). circuit-adversary exhaustively model-checked all 8.38M r values:
  SOUND verdict, 0 mismatches; its only note is the documented r<q precondition the
  M4 caller must honour (wp is a reduce_mod_q output, so satisfied). 32/32 lib tests
  pass. Oracle still RED by design (circuit_accepts is the M0 TODO(stub); usehint is
  internal gadgets only). Next: M4 SampleInBall + ExpandA rejection sampling (§3a
  fixed over-sampling with witnessed routing), then wire the §4 verify chain.
- M4 ExpandA sampling: added `src/sampling.rs` (private `mod sampling`) — `rej_ntt_poly`
  (FIPS-204 Alg-30 / RejNTTPoly), the NTT-domain `Â[r][s]`. Absorbs `ρ ∥ s ∥ r` into
  SHAKE128 (5th input word = `s | r<<8`), squeezes the fixed 840 B (5 blocks =
  280 three-byte candidates), computes per-candidate `z=((b2&0x7F)<<16)|(b1<<8)|b0`
  and `accept = select(icmp_ult(z,q),1,0)` (the icmp IS both the rejection test and
  the coeff range-check; select canonicalises the MSB-bool to a tight 0/1). Compaction
  via sound witnessed routing: a self-populating custom `ExpandACompactionHint` advises
  `src[k]`; the gadget reads `[accept, rank, z]` (rank = exclusive prefix sum of accept)
  from candidate `src[k]` through one `multi_wire_multiplex`, asserts `accept==1 ∧
  rank==k` — since rank strictly increases at accepted candidates this pins `src[k]` to
  the unique k-th accepted candidate, zero prover freedom (out-of-range src still lands
  on a real candidate, so the asserts bite identically). The `rank==255` slot forces
  ≥256 acceptances; the ~10⁻⁴⁴ >840B fallback is the documented omission. The hint is
  the only new nondeterminism and is fully re-pinned by constraints (no range-check
  needed). 3 property tests green vs an independent sha3-driven reference (random ρ/r/s
  round-trip, s-vs-r absorb-order separation, wrong-output rejection). circuit-adversary
  red-teamed all routing/forge/desync/byte-index/packing surfaces incl. a standalone
  280-leaf mux model: verdict SOUND. 35/35 lib tests pass. Oracle still RED by design
  (circuit_accepts is the M0 TODO(stub); sampling is an internal gadget). Next: M4
  SampleInBall (stateful ±1 shuffle via running-threshold scan), then wire the §4
  verify chain (decode→NTT→ExpandA→pointwise→NTT⁻¹→UseHint→w1→c̃′ equality).
- M4 SampleInBall: added `sample_in_ball` to `src/sampling.rs` (FIPS-204 Alg-29 /
  `ml-dsa/src/sampling.rs:66`), the sparse challenge `c=SampleInBall(c̃,τ=49)`. Pure
  deterministic over c̃ (6 words) — no hints/advice, zero prover freedom, so no new
  range-checks (like the decode gadgets). Two data-dependent control structures made
  fixed-shape: (1) index rejection sampling → a fixed 272 B SHAKE256 squeeze (8 sign
  bytes ∥ 264 index candidates) scanned once with a running (i_cur,k_cur) state,
  invariant i_cur=207+k_cur, accept⇔a≤i_cur ∧ k_cur<τ, scatter accepted byte into
  slot k_cur, final assert k_cur==τ (omitted >272B fallback ~10⁻³⁰⁰, SPEC §3a);
  (2) the τ-step in-place shuffle c[i]=c[j];c[j]=±1 with i a compile-time constant
  and j=j[t]≤i a wire — one single_wire_multiplex over c[0..=i] reads old c[j], then
  per-position rebuild (p==j wins, covering j==i; else p==i gets old c[j]; else
  unchanged); sign = bit t of the sign word (−1=q−1 if set). 3 property tests green
  vs an independent sha3-Shake256 reference (random round-trip + τ-nonzero/{±1}
  sanity, sign-flip rejection, input-dependence). circuit-adversary model-checked
  200k–3M seeds across the j==i edge, scan threshold/guard/scatter, mux range, sign
  indexing and completeness: verdict SOUND, 0 mismatches. 38/38 lib tests pass.
  Oracle still RED by design (circuit_accepts is the M0 TODO(stub); SampleInBall is
  an internal gadget). All M4 sub-gadgets now exist (decode, NTT, ExpandA, UseHint,
  SampleInBall). Next: wire the §4 single-sig verify chain in circuit_accepts —
  decode→SampleInBall/NTT(c)→NTT(z)→ExpandA→Âẑ−ĉt̂→NTT⁻¹→UseHint→w1 encode→c̃′ via
  μ/tr SHAKE256→c̃ equality, exposing key/sig bytes as inout/witness wires.

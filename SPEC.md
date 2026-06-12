# SPEC — ML-DSA-65 N-of-M verification in Binius64

> Produced by a plan-mode pass, approved by a human, frozen before the loop runs.
> The loop implements this; it does not redesign it mid-flight. If the loop finds
> the spec is wrong, it must stop and surface the contradiction, not improvise.

## 0. Statement being proved
Public (inout): `Policy{n,m}`, 64-byte message `M`, the `m` ML-DSA-65 verifying
keys. Private (witness): `n` ML-DSA-65 signatures. The circuit is satisfiable iff
at least `n` of the supplied signatures are valid ML-DSA-65 signatures on `M` under
distinct published keys — byte-for-byte the statement `default_verifier::verify_all`
decides, and the same statement `sp1-prover` proves.

## 0a. Verified parameters & facts (ML-DSA-65)
Read off the read-only `ml-dsa` reference (the numbers the circuit must honour):
- Field: `q = 2²³ − 2¹³ + 1 = 8380417` (23-bit). Plain residues mod q (non-Montgomery).
- `K = 6` (rows of A), `L = 5` (cols), `η = 4`, `γ1 = 2¹⁹`, `γ2 = (q−1)/32`,
  `2γ2 = 523776`, `τ = 49`, `β = τ·η = 196`, `ω = 55`, `d = 13`.
- `W1Bits = 4` (`m = (q−1)/(2γ2) = 16`); `λ` ⇒ `c̃ = 48 bytes`.
- Encoded sizes: verifying key 1952 B (ρ 32 ∥ t1 1920); signature 3309 B
  (c̃ 48 ∥ z 3200 ∥ h 61). Message `M` is 64 B; context is empty in the oracle path.
- Hashes: `G = SHAKE128`, `H = SHAKE256` (FIPS 202 XOFs, pad `0x1F`), from the `sha3`
  crate (`ml-dsa/src/crypto.rs`).
- Reference call chain the oracle exercises: `default_verifier::verify_all` →
  `VerifyingKey::verify` → `multipart_verify` → `raw_verify_with_context(_, ctx=&[], _)`
  → `verify_mu` → **`raw_verify_mu`** (`verifying.rs:106`).

## 1. Crate layout (`binius-prover`)
Single host crate (no guest/host split — Binius64 is not a zkVM). Mirror the
`sp1-prover` CLI surface so RESULTS.md columns line up:
- `cargo run -p binius-prover --release` — build circuit, populate honest witness,
  `verify_constraints`, print constraint stats (no proof).
- `-- --prove` — also generate + verify a Binius64 proof; print time/size.
- `cargo test -p binius-prover --test xcheck` — the oracle (see tests/xcheck.rs).
Public API consumed by xcheck (this is a contract — do not change signatures):
`build(&Policy) -> Circuit`, `circuit_accepts(&Circuit, &Case) -> Result<(),_>`,
`prove_and_verify(&Circuit, &Case) -> Result<ProofStats,_>`, and `Case`.

## 2. Field & polynomial layer — DECISIONS
Binius64 has no native Z_q. q = 8380417 = 2²³ − 2¹³ + 1 (23-bit). Coefficients are
plain residues mod q (the reference is **not** Montgomery: `ntt.rs` reduces with
`% BaseField::QL`). The single most important consequence: **q is single-word**, so
all field arithmetic stays in one 64-bit `Wire` — we do **not** use
`binius_circuits::bignum` (that is for the 256-bit ECDSA case in `ethsign`).

- `mul_mod_q(a, b)` — single-word, hint-reduced. With `a, b ∈ [0, q)` the integer
  product `p = a·b < q² < 2⁴⁶` fits the low word of `imul`:
  - `let (hi, lo) = b.imul(a, b);` then `b.assert_zero("mulq_hi", hi)` (provably 0
    for ≤23-bit inputs) and treat `p = lo`.
  - A divmod **hint** supplies `(k, r)` with `p = k·q + r`. Obtain it via a
    single-word divmod hint — either `b.biguint_divide_hint(&[p], &[Q])` with
    one-limb slices, or a tiny custom `ModQHint` registered through `b.call_hint`.
  - Constrain `k·q + r == p`: compute `k·q` with a second `imul` (k < q, so
    `k·q < 2⁴⁶`, low word, no 64-bit wrap), `iadd` the `r`, `assert_eq` against `p`.
  - **Range-check the remainder** — the crux of soundness:
    `b.assert_true("r<q", b.icmp_ult(r, Q))` and `b.assert_true("k<q",
    b.icmp_ult(k, Q))`. The check is a single `icmp_ult` against the constant `Q`
    (`add_constant_64(8380417)`) — i.e. **comparison, not lookup or bit-decomposition**
    (binius64 ships no range-lookup gadget). This is the single-word analogue of
    `ethsign`'s `biguint_lt` remainder check. Bit widths: operands 23-bit, products
    46-bit, `k·q` 46-bit — all comfortably inside one 64-bit word, so no carry/limb
    handling is needed.
  - Lazy reduction: an NTT-domain dot product accumulates ≤ L = 5 pointwise products
    (`< 5·2⁴⁶ < 2⁴⁹`, still one word); reduce **once** at the end of the accumulation,
    not per term — fewer hints and range-checks.

- `add_mod_q` / `sub_mod_q` — conditional subtract, deterministic (no hint, no
  range-check; operands are already reduced):
  - `add_mod_q(a, b)`: `let s = iadd(a, b).0;` (`s < 2q < 2²⁴`, no carry out of the
    word) then `select(icmp_uge(s, Q), s − Q, s)`.
  - `sub_mod_q(a, b)`: `select(icmp_ult(a, b), iadd(isub(a, b), Q).0, isub(a, b))`
    (equivalently `a + (Q − b)` then a conditional subtract of `Q`).
  - Both yield canonical results in `[0, q)`, preserving the invariant `mul_mod_q`
    relies on. Cost per op: one `icmp`, one `select`, one add/sub — no `imul`.

- Polynomial mult in R_q = Z_q[x]/(x²⁵⁶ + 1): **NTT, not schoolbook.** Two reasons:
  1. The reference verify is already NTT-structured — `Â = ExpandA(ρ)` is sampled
     **directly in the NTT domain** (`sampling.rs:97`), and the whole computation is
     `NTT(z)`, `NTT(c)`, pointwise products, then a single `NTT⁻¹` (`verifying.rs`).
     Mirroring it gives bit-identical intermediates, so witness population is trivial
     and the differential agreement with the reference is exact.
  2. Constraint count (`n_intmul` dominates): schoolbook = 256² = 65 536 modmuls per
     product × (K·L + K = 36 products) ≈ **2.36 M** modmuls plus negacyclic fix-ups.
     NTT path: forward NTT = 8 layers × 128 butterflies × 1 modmul = 1024 modmuls/poly
     × 6 polys (z: L = 5, c: 1) = 6144; pointwise (36 × 256) = 9216; inverse NTT × 6 =
     6144; ×256⁻¹ scaling = 1536. Total ≈ **23 k** modmuls — about 100× fewer. Each
     modmul carries the `imul` + hint + range-check cost, so NTT wins decisively on
     `n_intmul` and `n_witness_words`.
  - Use the exact FIPS 204 NTT (`ntt.rs`): ζ = 1753, table
    `ZETA_POW_BITREV[i] = ζ^bitrev8(i)` (Appendix B), 8 Cooley–Tukey butterfly layers
    forward (sub-block sizes 128→1), 8 Gentleman–Sande layers inverse with negated
    twiddles, then ×256⁻¹ (= 8 347 681). Twiddles are circuit constants
    (`add_constant_64`); butterflies are built from `add_mod_q` / `sub_mod_q` /
    `mul_mod_q`. (Optional: NTT(c) could be specialised since c is sparse ±1
    weight-49; negligible — skip for M2.)

- Coefficient packing: **one Z_q coefficient per 64-bit `Wire`** for all arithmetic.
  Sub-word packing would force an unpack before every mod-q op (the gadgets operate on
  whole words), so it is both correct and cheapest to keep one coeff per wire. A
  degree-256 polynomial is 256 wires; vectors are K- or L-arrays of those. Byte-level
  packing only matters at the SHAKE I/O boundary (8 bytes/word). Decode of the
  on-the-wire byte encodings into coefficient wires (the public-`inout` bytes ↔
  coefficient-wire bridge):
  - **t1** (vk, after the 32-byte ρ): `Encode::<10>`, 10 bits/coeff → 320 B/poly,
    K = 6 → 1920 B (vk = ρ 32 ∥ t1 1920 = 1952 B). Then form 2¹³·t1 (with t1 < 2¹⁰ the
    product is < 2²³ < q, so no reduction) and `NTT` it → `t1_2d_hat`.
  - **z** (sig, after the 48-byte c̃): `BitPack::<γ1−1, γ1>`, γ1 = 2¹⁹ → 20 bits/coeff
    → 640 B/poly, L = 5 → 3200 B. Coefficient = γ1 − field ∈ [−(γ1−1), γ1], stored mod
    q. Decode never fails (any 20-bit field is valid) and **no ‖z‖∞ bound is enforced**
    — see §4.
  - **c̃** (sig, first 48 B = λ): consumed twice — as the SHAKE256 input to SampleInBall,
    and as the equality target against the recomputed c̃′. Held as 48 B / 6 words.
  - **h** (sig, last 61 B = ω + K = 55 + 6): ω index bytes then K cut bytes. Decode to
    K × 256 hint bits while enforcing the `bit_unpack` validity rules (cuts
    non-decreasing; max cut ≤ ω; indices beyond max-cut are zero; per-segment indices
    strictly increasing). A malformed hint ⇒ reject. **This — not a separate verify
    step — is where the hint-weight ≤ ω bound actually lives.**
  - **w1** (recomputed, internal): `Encode::<4>` (W1Bits = 4 for ML-DSA-65, since
    m = (q−1)/(2γ2) = 16 ⇒ values 0..15) → 128 B/poly, K = 6 → 768 B; this is the byte
    string absorbed (with μ) into SHAKE256 to produce c̃′.
  - The byte↔coefficient packing is fixed-shape (compile-time) using `shl` / `shr` /
    `band` / `extract_byte`, and `binius_frontend::util::pack_bytes_into_wires_le` on
    the byte/word side.

## 3. Hashing layer
ML-DSA-65 uses SHAKE-128 (ExpandA) and SHAKE-256 (μ, tr, challenge c̃, SampleInBall).
The reference (`ml-dsa/src/crypto.rs`) uses the **`sha3` crate** — `G = Shake128`,
`H = Shake256` — i.e. standard FIPS 202 XOFs with domain pad **`0x1F`**. (The crate
was switched from a `shake` crate to `sha3` for an SP1 precompile; semantics are
unchanged.)

**There is no SHAKE gadget in `binius_circuits`** (this corrects the original draft).
What exists:
- `binius_circuits::keccak::Keccak256` — variable-length **Keccak-256** (Ethereum pad
  `0x01 … 0x80`, rate 136, *fixed* 256-bit digest, **no XOF squeeze**). Unusable for
  ML-DSA: wrong pad and no extendable output.
- `binius_circuits::keccak::permutation::{Permutation, State}`, exposing the reusable
  primitive `Permutation::keccak_f1600(b: &CircuitBuilder, state: &mut [Wire; 25])`
  (`N_WORDS_PER_STATE = 25`). **This is the building block.**

So build SHAKE128/SHAKE256 sponges in-crate on `keccak_f1600`:
- Exact import: `use binius_circuits::keccak::permutation::{Permutation, State};`
- Rate: SHAKE128 = 168 B = 21 words; SHAKE256 = 136 B = 17 words; capacity is the rest
  of the 25-word (1600-bit) state.
- Absorb: XOR each rate block of message words into the leading r/8 state words
  (`bxor`), apply `keccak_f1600`, repeat.
- Pad: append the XOF domain byte **`0x1F`** after the message, then set `0x80` in the
  last byte of the final rate block. (NB: `0x1F`, **not** the gadget's Keccak `0x01`
  nor SHA3-256's `0x06`.)
- Squeeze: read the leading r/8 state words as output; for more than one rate of
  output, apply `keccak_f1600` again and continue (XOF). Every absorb/squeeze length
  here is public (compile-time known), so each sponge unrolls to a fixed number of
  permutations — no data-dependent loop.

Reuse the `ethsign` example (`crates/examples/src/circuits/ethsign.rs` in binius64) as
the reference for "verify a signature inside a Binius64 circuit": it declares the
message/signature/key as `inout` and intermediate states as `witness`, derives the
verifying condition, `assert_*`s it, and composes per-signature subcircuits with
`(0..n_signatures).map(...)` — the same shape as our N-of-M aggregation (§5). Its
modular-arithmetic pattern (witness `(quotient, remainder)`, constrain `a·b = q·m + r`,
range-check `r < m` via `biguint_lt`) **is** `mul_mod_q` — but single-word for us, so we
skip its 256-bit `bignum`. Shared imports:
`binius_frontend::{CircuitBuilder, Wire, WitnessFiller, util::{pack_bytes_into_wires_le,
byteswap}}` and `binius_core::word::Word`.

### 3a. ExpandA / SampleInBall rejection sampling — fixed over-sampling
Rejection sampling has data-dependent control flow, which a circuit cannot have. The
reference already resolves this with **fixed over-sampling**, and we mirror it.

**ExpandA** (`Â[r][s] = RejNTTPoly(ρ, r, s)`, `sampling.rs:97`), per row r, column s:
- Absorb `ρ (32 B) ∥ s ∥ r` into SHAKE128 — note the byte order is `s` then `r`
  (`absorb(ρ).absorb(&[s]).absorb(&[r])`, with r = row index, s = column index).
- Squeeze **exactly 840 bytes = 5 SHAKE128 rate blocks = 5 `keccak_f1600`
  permutations** — the same fixed buffer the reference squeezes — giving
  **280 three-byte candidates**.
- Per candidate: `z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0`;
  `accept = b.icmp_ult(z, Q)`. This `icmp_ult` **is** the rejection test and the
  range-check in one. The first 256 accepted candidates are the polynomial's NTT
  coefficients (Â is already in the NTT domain).
- Compaction (the data-dependent part) by **witnessed routing, constrained for
  soundness**: advise, for each output position k ∈ 0..256, the source candidate index;
  constrain (a) that candidate is accepted, (b) the routing is the order-preserving
  ("stable") compaction of accepted candidates — checked by a prefix-count match — and
  (c) the accepted count reaches 256. (Cheaper alternative with no advice: compute the
  accept bits, a prefix-sum rank, and scatter through `binius_circuits::multiplexer`,
  at the cost of more `select`s.)
- The reference's unbounded fallback (`sampling.rs:119`) is **omitted**: it triggers
  with probability ≈ 10⁻⁴⁴ per polynomial, and Â is a deterministic function of the
  **public** ρ — the prover has zero witness freedom in Â — so the only effect of
  omission is that a ρ needing the fallback would make the circuit unsatisfiable, an
  event that never occurs for real keys or the test corpus. This is the one documented,
  unobservable divergence from the reference (see Corrections).

**SampleInBall** (`c = SampleInBall(c̃, τ=49)`, `sampling.rs:66`) uses the same pattern:
absorb c̃ into SHAKE256, squeeze 8 sign bytes plus a fixed over-sampled index stream,
and select τ = 49 swap positions. Its acceptance threshold `i` increments per accepted
sample (the `while j[0] > i` loop), so the per-step predicate is `j ≤ i` with `i`
advancing; budget the SHAKE256 squeeze so 49 acceptances occur with overwhelming
probability and drop the analogous fallback. Result: a length-256 polynomial with
exactly τ nonzero coefficients ∈ {−1, 0, 1}.

## 4. ML-DSA-65 verify, in-circuit (FIPS 204)
The oracle is differential against the RustCrypto reference, so the circuit must
reproduce **`raw_verify_mu`** (`verifying.rs:106`) exactly, which decides
**accept ⇔ c̃ = c̃′** — and nothing else. Enumerated as explicit constraints per
signature:
1. **Decode** the signature: c̃ (48 B), z = `BitUnpack₂₀` (always succeeds),
   h = `Hint::bit_unpack` — emit the **hint-encoding validity constraints** (cuts
   non-decreasing; max cut ≤ ω; indices past max-cut are zero; per-segment strictly
   increasing). Any violation makes the subcircuit unsatisfiable ⇒ that signature is
   rejected, matching the reference's `None`.
2. `c = SampleInBall(c̃, 49)` — fixed over-sampling (§3a); exactly τ nonzero ∈{−1,0,1}.
3. `ĉ = NTT(c)`, `ẑ = NTT(z)`.
4. `Â = ExpandA(ρ)` — NTT domain, fixed over-sampling (§3a).
5. `Âẑ = Â · ẑ` (matrix·vector: pointwise products accumulated mod q over L);
   `ĉt = ĉ · t1_2d_hat`, where `t1_2d_hat = NTT(2¹³·t1)` (pointwise over K).
6. `wp = NTT⁻¹(Âẑ − ĉt)` (K polynomials).
7. `w1 = UseHint(h, wp)` (`hint.rs:25`): per coefficient, Decompose `wp` into `(r1, r0)`
   mod 2γ2 (`wp ≡ 2γ2·r1 + r0`, r0 centred — every relation mod-q range-checked); then
   `h = 0 ⇒ r1`; `h = 1 ⇒ (0 < r0 ≤ γ2) ? (r1+1 mod 16) : (r1+15 mod 16)`.
8. `w1_enc = Encode₄(w1)` (768 B).
9. `c̃′ = H(μ ∥ w1_enc)[..48]`; `μ = H(tr ∥ 0x00 ∥ 0x00 ∥ M)[..64]`;
   `tr = H(vkEncode)[..64]` (`H = SHAKE256`; MuBuilder `lib.rs:165–190`; the
   `verify_all` path has empty ctx, hence the two `0x00` bytes).
10. **Accept ⇔ `assert_eq` of c̃ vs c̃′** over the 6 words — gated into the N-of-M
    decision (§5).

**Correction (the original draft over-stated the checks):** `raw_verify_mu` performs
**no `‖z‖∞ < γ1−β` norm check** (z is unconstrained beyond its 20-bit decode) and **no
explicit hint-weight check** (the ≤ ω bound is enforced only structurally — there are
just ω index slots and decode validity, item 1). Adding the FIPS 204 Alg-8 norm/weight
rejections would risk a differential disagreement (the circuit rejecting an input the
reference accepts) and is unnecessary. The "range checks" that genuinely matter for
soundness are the **mod-q remainder range-checks on every nondeterministic reduction**
(§2) and the candidate-acceptance checks (§3a) — not ML-DSA norm bounds. This is a
deliberate deviation from FIPS 204, forced by the chosen oracle
(`default_verifier::verify_all` → `ml-dsa`); see Corrections.

## 5. N-of-M aggregation
Compose `n` per-signature subcircuits; enforce distinct key slots; accept iff all
`n` pass. Match `verify_all` exactly (fewer signers or any bad signature ⇒ unsat).

## 6. Done = the oracle is green
`cargo test -p binius-prover --test xcheck` passes for all policies in the corpus,
with soundness (corrupted ⇒ unsat), differential agreement with the reference, and
honest cases proving + verifying. RESULTS.md updated with n_bitand / n_intmul /
n_witness_words / build / prove time / proof size, alongside the SP1 columns.

## 7. Milestone order (the loop advances one at a time; see progress.json)
M0 scaffold+CLI · M1 mod-q gadgets (property-tested) · M2 R_q poly mult · M3 hashing+decode
· M4 single-sig verify (differential + tamper) · M5 N-of-M · M6 prove+verify+RESULTS.

## 8. Corrections vs original draft (verified 2026-06-12, binius64 @ 8f21b34)
The §2–§4 blanks were filled against primary sources (binius64 `main`
`binius-zk/binius64` rev `8f21b348fe8e8327b63ffa06884bf1783d40635f`, and the local
`ml-dsa` crate). Four points correct or qualify the original draft:
1. **No SHAKE gadget exists.** `binius_circuits` ships only a Keccak-256 gadget
   (Ethereum pad `0x01`, fixed 256-bit digest, no XOF). SHAKE128/256 must be built
   in-crate on `keccak::permutation::Permutation::keccak_f1600` with the XOF pad `0x1F`
   (§3).
2. **The reference decides on c̃ equality alone.** `raw_verify_mu` does no `‖z‖∞ < γ1−β`
   norm check and no explicit hint-weight check — so the circuit must not add them, on
   pain of differential disagreement (§4). The hint-weight ≤ ω bound lives only in
   hint-decode validity.
3. **ExpandA and SampleInBall use fixed over-sampling**, mirroring the reference's
   fixed 840-byte (ExpandA) squeeze; the astronomically-unlikely (~10⁻⁴⁴) fallback is
   omitted. Â is a deterministic function of the public ρ, so this is sound and
   unobservable on real inputs (§3a).
4. **`verify_all` does not enforce key distinctness** — it positionally zips the first
   n signatures with the first n keys and counts validity (`valid >= n`). So §0/§5's
   "distinct keys/slots" must be realised, if at all, only as positional pairing; do
   **not** add a key-distinctness constraint in M5, or honest cases with repeated keys
   could diverge from the reference. The threshold to match is exactly
   `valid_count >= policy.n` over those positional pairs.

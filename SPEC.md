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

## 2. Field & polynomial layer — DECISIONS TO FILL IN
Binius64 has no native Z_q. q = 8380417 (23-bit). Fill in:
- `mul_mod_q`: `imul` → nondeterministic (quotient, remainder) hint, with range
  checks proving `0 ≤ r < q` and `p = q·quotient + r`. Specify the range-check
  gadget (decompose vs. lookup) and the bit widths. ____
- `add_mod_q` / `sub_mod_q`: conditional subtract of q. Specify. ____
- Polynomial mult in R_q = Z_q[x]/(x²⁵⁶+1): **NTT vs schoolbook** — pick one and
  justify on constraint count (n_intmul dominates). ____
- Coefficient packing: how many Z_q coeffs per 64-bit word; how `t1`/`z`/`c` decode
  from their on-the-wire byte encodings into coefficient wires. ____

## 3. Hashing layer
SHAKE-128 (ExpandA) and SHAKE-256 (mu, challenge seed, SampleInBall) via the
keccak gadget in `binius_circuits`. Confirm the gadget name/import and the
absorb/squeeze rate handling. ____ Reuse the `ethsign` example as the reference
for "verify a signature inside a Binius64 circuit". ____

## 4. ML-DSA-65 verify, in-circuit (FIPS 204)
Per signature: decode `(c̃, z, h)`; reject if `‖z‖∞ ≥ γ1−β` (range checks);
`c = SampleInBall(c̃)`; `A = ExpandA(ρ)`; `w'Approx = NTT⁻¹(A·NTT(z) − NTT(c)·NTT(t1·2^d))`;
`UseHint(h, w'Approx) = w1`; recompute `c̃' = H(μ ‖ w1Encode)`; accept iff `c̃' = c̃`
and the hint weight bound holds. Enumerate every range/weight check as an explicit
constraint — a missing one is an under-constraint the oracle will catch. ____

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

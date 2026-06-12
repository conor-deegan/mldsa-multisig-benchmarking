//! Rejection sampling for `ExpandA`.
//!
//! `Â = ExpandA(ρ)` is sampled **directly in the NTT domain** (FIPS-204 Alg. 32 /
//! `ml-dsa/src/sampling.rs:97` `RejNTTPoly`). For each matrix entry `Â[r][s]` the
//! reference absorbs `ρ ∥ s ∥ r` into SHAKE128, squeezes a fixed 840-byte buffer
//! (5 Keccak-f permutations = 280 three-byte candidates), maps each candidate to
//! `z = ((b₂ & 0x7F) << 16) | (b₁ << 8) | b₀` and keeps it iff `z < q`. The first
//! 256 accepted candidates are the polynomial's coefficients.
//!
//! A circuit cannot branch on the data-dependent rejection, so — exactly as the
//! reference does — we mirror its **fixed over-sampling**: squeeze the
//! same 840 bytes, compute an `accept` bit per candidate, and select the first 256
//! accepted by **witnessed routing constrained for soundness**. The routing advice
//! (which source candidate feeds each output slot) comes from a self-populating
//! custom [`Hint`] so the gadget needs no externally-supplied witness, just like
//! [`crate::field`]'s divmod hint.
//!
//! ### Why the routing is sound
//! For output slot `k` the advice names a source candidate; three values are read
//! from that candidate through identical-shape multiplexers — its `accept` bit, its
//! **exclusive prefix rank** (how many candidates before it were accepted), and its
//! `z`. We then assert `accept == 1` and `rank == k`. Because the prefix rank
//! strictly increases at every accepted candidate, those two assertions are
//! satisfied by **exactly one** candidate — the `(k+1)`-th accepted one — so `z` is
//! pinned with no prover freedom. `Â` is therefore a deterministic function of the
//! public `ρ`, matching the reference coefficient-for-coefficient. (Out-of-range
//! advice cannot cheat: the multiplexer still resolves to *some* real candidate and
//! reads all three of its values consistently, so the rank/accept assertions bite
//! just the same.) Requiring slot `k = 255` to be filled forces ≥ 256 acceptances;
//! the reference's astronomically-unlikely (~10⁻⁴⁴) >840-byte fallback is omitted,
//! the one documented, corpus-unobservable divergence.

#![allow(dead_code)]

use binius_circuits::multiplexer::single_wire_multiplex;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Hint, Wire};

use crate::field::{FieldConsts, Q};

/// Degree of every polynomial: 256 coefficients.
pub const N: usize = 256;

/// Fixed ExpandA squeeze: 840 bytes = 5 SHAKE128 rate blocks = 280 candidates.
pub const EXPAND_A_BYTES: usize = 840;

/// Number of three-byte rejection-sampling candidates in the 840-byte buffer.
pub const N_CANDIDATES: usize = EXPAND_A_BYTES / 3; // 280

/// Self-populating advice for the ExpandA compaction. Given one
/// `accept` word (0 or 1) per candidate, it returns, for each of the 256 output
/// slots, the index of the candidate that fills it — the `k`-th accepted candidate
/// in input order. Slots with no corresponding acceptance are left zero (the
/// in-circuit `rank == k` assertion then makes the witness unsatisfiable, which only
/// happens for the omitted >840-byte fallback case).
///
/// `dimensions = [n_candidates, n_out]`. This hint is *only* a witness shortcut: its
/// output is fully re-pinned by the gadget's constraints, so a wrong or adversarial
/// hint cannot make an invalid `Â` accepted — see the module docs.
struct ExpandACompactionHint;

impl Hint for ExpandACompactionHint {
    const NAME: &'static str = "mldsa.expand_a.compaction";

    fn shape(&self, dimensions: &[usize]) -> (usize, usize) {
        let [n_candidates, n_out] = dimensions else {
            panic!("ExpandACompactionHint requires [n_candidates, n_out]");
        };
        (*n_candidates, *n_out)
    }

    fn execute(&self, dimensions: &[usize], inputs: &[Word], outputs: &mut [Word]) {
        let [_n_candidates, n_out] = dimensions else {
            panic!("ExpandACompactionHint requires [n_candidates, n_out]");
        };
        let mut k = 0usize;
        for (i, w) in inputs.iter().enumerate() {
            if k == *n_out {
                break;
            }
            if w.as_u64() & 1 == 1 {
                outputs[k] = Word::from_u64(i as u64);
                k += 1;
            }
        }
        // Pad any unfilled slots (under-acceptance, the omitted fallback case).
        for o in outputs[k..].iter_mut() {
            *o = Word::ZERO;
        }
    }
}

/// `RejNTTPoly(ρ, r, s)` (FIPS-204 Alg. 30): the NTT-domain polynomial `Â[r][s]`.
///
/// `rho` is the 32-byte seed as 4 little-endian words (the public verifying key's ρ);
/// `r` (row) and `s` (column) are compile-time matrix indices. Returns the 256
/// NTT-domain coefficient wires, each a canonical residue in `[0, q)`.
///
/// Absorbs `ρ ∥ s ∥ r` (note the reference's `s`-then-`r` order) into SHAKE128 and
/// squeezes the fixed 840-byte buffer, then compacts via the sound witnessed routing
/// described in the module docs.
pub fn rej_ntt_poly(b: &CircuitBuilder, rho: &[Wire], r: u8, s: u8) -> Vec<Wire> {
    assert_eq!(rho.len(), 4, "ρ is 32 bytes = 4 words");

    let zero = b.add_constant_64(0);
    let one = b.add_constant_64(1);
    let q = b.add_constant_64(Q);

    // ── SHAKE128(ρ ∥ s ∥ r) → 840 bytes ───────────────────────────────────────
    // The 33rd/34th bytes (s then r) share the 5th input word, little-endian.
    let mut msg = rho.to_vec();
    msg.push(b.add_constant_64((s as u64) | ((r as u64) << 8)));
    let out_words = crate::shake::shake128(b, &msg, 32 + 2, EXPAND_A_BYTES);

    // Carve the 840 squeezed bytes out of the packed output words.
    let byte = |g: usize| b.extract_byte(out_words[g / 8], (g % 8) as u32);

    // ── Per-candidate value z and acceptance bit ──────────────────────────────
    // z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0; accept ⇔ z < q. The `icmp_ult`
    // *is* both the rejection test and the coefficient range-check.
    let mask7f = b.add_constant_64(0x7F);
    let mut z = Vec::with_capacity(N_CANDIDATES);
    let mut accept = Vec::with_capacity(N_CANDIDATES); // 0/1 words
    for c in 0..N_CANDIDATES {
        let b0 = byte(3 * c);
        let b1 = byte(3 * c + 1);
        let b2 = byte(3 * c + 2);
        let hi = b.shl(b.band(b2, mask7f), 16);
        let mid = b.shl(b1, 8);
        let zc = b.bor(b.bor(hi, mid), b0);
        // Canonicalise the MSB-bool comparison to a 0/1 integer for the prefix sum.
        let acc = b.select(b.icmp_ult(zc, q), one, zero);
        z.push(zc);
        accept.push(acc);
    }

    // ── Exclusive prefix rank: rank[c] = #accepted among candidates < c ────────
    // Strictly increasing at accepted candidates, which is what pins routing.
    let mut rank = Vec::with_capacity(N_CANDIDATES);
    let mut running = zero;
    for c in 0..N_CANDIDATES {
        rank.push(running);
        running = b.iadd(running, accept[c]).0; // ≤ 280, never carries
    }

    // ── Compaction by sound witnessed routing ─────────────────────────────────
    let src = b.call_hint(ExpandACompactionHint, &[N_CANDIDATES, N], &accept);

    // Pack each candidate's [accept, rank, z] into a single 64-bit wire so the
    // per-slot read is **one** `single_wire_multiplex` (279 selects) rather than
    // three (837) — a 3× cut on the dominant ExpandA cost, with the soundness
    // argument unchanged (the three fields are unpacked back out and asserted
    // identically). Layout: z in bits [0,23) (< q < 2²³), rank in [23,32)
    // (≤ 280 < 2⁹), accept at bit 33. No fields overlap.
    let mask23 = b.add_constant_64((1u64 << 23) - 1);
    let mask9 = b.add_constant_64((1u64 << 9) - 1);
    let packed: Vec<Wire> = (0..N_CANDIDATES)
        .map(|c| {
            let r_sh = b.shl(rank[c], 23);
            let a_sh = b.shl(accept[c], 33);
            b.bor(b.bor(z[c], r_sh), a_sh)
        })
        .collect();

    (0..N)
        .map(|k| {
            let sel = src[k];
            let p = single_wire_multiplex(b, &packed, sel);
            let z_sel = b.band(p, mask23);
            let rank_sel = b.band(b.shr(p, 23), mask9);
            let a_sel = b.shr(p, 33);
            // The selected candidate must be accepted and have prefix rank exactly k;
            // together these identify the unique k-th accepted candidate, pinning z.
            b.assert_eq("expandA_routed_accept", a_sel, one);
            b.assert_eq("expandA_routed_rank", rank_sel, b.add_constant_64(k as u64));
            z_sel
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// SampleInBall (FIPS-204 Alg. 29 / `ml-dsa/src/sampling.rs:66`)
// ─────────────────────────────────────────────────────────────────────────────

/// Number of nonzero coefficients in the challenge polynomial `c` (ML-DSA-65).
pub const TAU: usize = 49;

/// First iteration index of the shuffle: `256 − τ = 207` (the `for i in (256-τ)..256`
/// loop in the reference).
pub const SIB_FIRST: usize = N - TAU; // 207

/// Fixed over-sampled SHAKE256 squeeze for SampleInBall: 8 sign bytes followed by the
/// index-candidate stream. Two SHAKE256 rate blocks (272 B) overwhelmingly cover the
/// τ = 49 acceptances — each accepted candidate clears a threshold `i ≥ 207`, so the
/// per-byte acceptance probability is `≥ 208/256`; the chance that 264 candidates yield
/// fewer than 49 acceptances is ~10⁻³⁰⁰, far below any cryptographic margin. The
/// reference's unbounded squeeze (the `while j[0] > i` loop) is replaced by this fixed
/// budget, mirroring the fixed over-sampling used for ExpandA; over-squeezed bytes are simply
/// never consumed (the `k < τ` guard gates them), so the produced `c` is identical.
pub const SAMPLE_IN_BALL_BYTES: usize = 272;

/// Number of index-candidate bytes (after the 8 sign bytes).
pub const N_INDEX_BYTES: usize = SAMPLE_IN_BALL_BYTES - 8; // 264

/// `c = SampleInBall(c̃, τ = 49)` (FIPS-204 Alg. 29): the sparse challenge polynomial,
/// 256 coefficients of which exactly τ are nonzero ∈ {−1, +1} (stored as the canonical
/// residues `q − 1` / `1`), the rest zero.
///
/// `ctilde` is the 48-byte challenge hash as 6 little-endian words (the signature's
/// first field). Returns 256 coefficient wires.
///
/// ### Construction (no nondeterminism, zero prover freedom)
/// `c` is a deterministic function of `c̃`, so — like the decode gadgets — this emits
/// only combinational/sequential gates over public-relation values and introduces no
/// witness advice and hence no range-checks. Two data-dependent control structures in
/// the reference are made fixed-shape:
///
/// 1. **Index rejection sampling.** The reference squeezes index bytes one at a time,
///    skipping any `> i` for the current threshold `i` (which starts at 207 and rises by
///    one per accepted sample). We squeeze the fixed [`SAMPLE_IN_BALL_BYTES`] stream and
///    scan it once, carrying a running `(i_cur, k_cur)` state: a byte `a` is accepted iff
///    `a ≤ i_cur ∧ k_cur < τ`, on which `i_cur` and `k_cur` both advance (the invariant
///    `i_cur = 207 + k_cur` holds throughout, so the threshold matches the reference's
///    `i` at every step). The accepted byte is scattered into output slot `k_cur`, giving
///    `j[0..τ]` — the same index sequence the reference consumes. A final `k_cur == τ`
///    assertion forces all τ acceptances to have occurred within the budget (the omitted
///    >272-byte fallback would make the witness unsatisfiable, an event of probability
///    ~10⁻³⁰⁰).
///
/// 2. **The in-place shuffle.** For iteration `t` (threshold/target index `i = 207 + t`,
///    a compile-time constant) the reference does `c[i] = c[j]; c[j] = ±1`. With `i`
///    constant and `j = j[t]` a wire (`≤ i`), each step reads `c[j]` via one
///    `single_wire_multiplex` over `c[0..=i]` then rebuilds the array: position `p`
///    becomes `±1` if `p == j` (the last write wins, also covering `j == i`), else
///    `c[j]` if `p == i`, else unchanged. The sign for iteration `t` is bit `t` of the
///    8 sign bytes (`bit_set(s, i + τ − 256) = bit_set(s, t)`), `−1` if set.
pub fn sample_in_ball(b: &CircuitBuilder, c: &FieldConsts, ctilde: &[Wire]) -> Vec<Wire> {
    assert_eq!(ctilde.len(), 6, "c̃ is 48 bytes = 6 words");

    let zero = c.zero;
    let one = b.add_constant_64(1);
    let minus_one = b.add_constant_64(Q - 1);
    let tau_w = b.add_constant_64(TAU as u64);

    // ── SHAKE256(c̃) → 272 bytes: 8 sign bytes ∥ index-candidate stream ─────────
    let out = crate::shake::shake256(b, ctilde, 48, SAMPLE_IN_BALL_BYTES);
    let byte = |g: usize| b.extract_byte(out[g / 8], (g % 8) as u32);
    // The 8 sign bytes are exactly the first output word, little-endian; bit t of it
    // is `bit_set(s, t)`, the sign selector for iteration t.
    let sign_word = out[0];

    // ── Fixed-length scan deriving j[0..τ] with the running threshold ──────────
    let mut j = vec![zero; TAU];
    let mut i_cur = b.add_constant_64(SIB_FIRST as u64); // 207
    let mut k_cur = zero;
    for q in 0..N_INDEX_BYTES {
        let a = byte(8 + q);
        let accept = b.band(b.icmp_ule(a, i_cur), b.icmp_ult(k_cur, tau_w));
        // Scatter the accepted byte into slot k_cur (the current iteration index).
        for (t, jt) in j.iter_mut().enumerate() {
            let hit = b.band(accept, b.icmp_eq(k_cur, b.add_constant_64(t as u64)));
            *jt = b.select(hit, a, *jt);
        }
        // Advance (i_cur, k_cur) together on acceptance; both stay < 2²⁴ (no carry).
        i_cur = b.select(accept, b.iadd(i_cur, one).0, i_cur);
        k_cur = b.select(accept, b.iadd(k_cur, one).0, k_cur);
    }
    // All τ acceptances must have landed inside the fixed budget.
    b.assert_eq("sib_count", k_cur, tau_w);

    // ── The τ-step in-place shuffle, c starting all-zero ───────────────────────
    let mut poly = vec![zero; N];
    for t in 0..TAU {
        let i = SIB_FIRST + t; // compile-time target index 207..255
        let jt = j[t];
        // Sign for iteration t: bit t of the sign word, −1 if set else +1.
        let bit = b.band(sign_word, b.add_constant_64(1u64 << t));
        let sign_val = b.select(b.icmp_ne(bit, zero), minus_one, one);
        // old_at_j = poly[j]; j ≤ i, so the i+1-wide mux covers it.
        let old_at_j = single_wire_multiplex(b, &poly[..=i], jt);
        poly = (0..N)
            .map(|p| {
                let base = if p == i { old_at_j } else { poly[p] };
                b.select(b.icmp_eq(b.add_constant_64(p as u64), jt), sign_val, base)
            })
            .collect();
    }
    poly
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{Shake128, Shake256};

    /// Independent plain-Rust reference for `RejNTTPoly` (FIPS-204 Alg. 30), driven
    /// by the `sha3` crate — the same reference the `ml-dsa` crate wraps but which is
    /// `pub(crate)` there, so we re-derive it here. Returns the 256 NTT-domain
    /// coefficients, panicking if 840 bytes did not yield 256 acceptances (so a test
    /// seed that would trip the omitted fallback is rejected up front, not silently).
    fn ref_rej_ntt_poly(rho: &[u8; 32], r: u8, s: u8) -> [u64; N] {
        let mut h = Shake128::default();
        h.update(rho);
        h.update(&[s]);
        h.update(&[r]);
        let mut xof = h.finalize_xof();
        let mut buf = [0u8; EXPAND_A_BYTES];
        xof.read(&mut buf);

        let mut out = [0u64; N];
        let mut j = 0usize;
        for chunk in buf.chunks_exact(3) {
            let z = (((chunk[2] & 0x7F) as u64) << 16) | ((chunk[1] as u64) << 8) | chunk[0] as u64;
            if z < Q {
                out[j] = z;
                j += 1;
                if j == N {
                    break;
                }
            }
        }
        assert_eq!(j, N, "test seed needed the omitted >840B fallback; pick another");
        out
    }

    /// Pack 32 ρ bytes into 4 little-endian words.
    fn pack_rho(rho: &[u8; 32]) -> [u64; 4] {
        let mut w = [0u64; 4];
        for (i, wi) in w.iter_mut().enumerate() {
            *wi = u64::from_le_bytes(rho[i * 8..i * 8 + 8].try_into().unwrap());
        }
        w
    }

    /// Build a one-poly ExpandA circuit, couple each coefficient output to a
    /// preloaded `want` inout (the field/NTT coupling trick — reading a fused output
    /// directly is rejected by gate fusion), and report whether the witness
    /// populates. A correct gadget matches `expected`; a wrong `expected` must fail.
    fn check(rho: &[u8; 32], r: u8, s: u8, expected: &[u64; N]) -> bool {
        let b = CircuitBuilder::new();
        let rho_wires: Vec<Wire> = (0..4).map(|_| b.add_inout()).collect();
        let out = rej_ntt_poly(&b, &rho_wires, r, s);
        let want: Vec<Wire> = (0..N).map(|_| b.add_inout()).collect();
        for (o, w) in out.iter().zip(&want) {
            b.assert_eq("coeff_eq", *o, *w);
        }
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        for (wire, val) in rho_wires.iter().zip(pack_rho(rho)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, val) in want.iter().zip(expected.iter()) {
            w[*wire] = Word::from_u64(*val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    #[test]
    fn rej_ntt_poly_matches_reference() {
        let mut rng = StdRng::seed_from_u64(101);
        for _ in 0..6 {
            let mut rho = [0u8; 32];
            rng.fill_bytes(&mut rho);
            let r = (rng.next_u64() % 6) as u8;
            let s = (rng.next_u64() % 5) as u8;
            let want = ref_rej_ntt_poly(&rho, r, s);
            assert!(check(&rho, r, s, &want), "rej_ntt_poly mismatch r={r} s={s}");
        }
    }

    /// Distinct (r, s) under the same ρ must give distinct polynomials, and each must
    /// match its own reference — catches an absorb-order (s vs r) mix-up.
    #[test]
    fn rej_ntt_poly_index_dependent() {
        let rho = [7u8; 32];
        let a = ref_rej_ntt_poly(&rho, 0, 1);
        let c = ref_rej_ntt_poly(&rho, 1, 0);
        assert_ne!(a, c, "ρ-fixed polys for (0,1) and (1,0) should differ");
        assert!(check(&rho, 0, 1, &a));
        assert!(check(&rho, 1, 0, &c));
    }

    /// A wrong expected coefficient must make the witness unsatisfiable — guards
    /// against a vacuously-passing coupling.
    #[test]
    fn rej_ntt_poly_rejects_wrong_output() {
        let rho = [3u8; 32];
        let mut want = ref_rej_ntt_poly(&rho, 2, 3);
        assert!(check(&rho, 2, 3, &want));
        want[0] ^= 1;
        assert!(!check(&rho, 2, 3, &want));
    }

    // ── SampleInBall ──────────────────────────────────────────────────────────

    /// Independent plain-Rust reference for `SampleInBall` (FIPS-204 Alg. 29), driven
    /// by the `sha3` crate's SHAKE256 — re-derived here since the `ml-dsa` version is
    /// `pub(crate)`. Returns the 256 coefficients as canonical residues (0, 1, q−1).
    fn ref_sample_in_ball(ctilde: &[u8; 48]) -> [u64; N] {
        let mut h = Shake256::default();
        h.update(ctilde);
        let mut xof = h.finalize_xof();
        let mut s = [0u8; 8];
        xof.read(&mut s);

        let mut c = [0u64; N];
        let mut jb = [0u8; 1];
        for i in (N - TAU)..N {
            loop {
                xof.read(&mut jb);
                if (jb[0] as usize) <= i {
                    break;
                }
            }
            let j = jb[0] as usize;
            c[i] = c[j];
            let idx = i + TAU - N; // = i − 207 ∈ 0..τ
            let bit = (s[idx >> 3] >> (idx & 7)) & 1;
            c[j] = if bit == 1 { Q - 1 } else { 1 };
        }
        c
    }

    /// Pack 48 c̃ bytes into 6 little-endian words.
    fn pack_ctilde(ct: &[u8; 48]) -> [u64; 6] {
        let mut w = [0u64; 6];
        for (i, wi) in w.iter_mut().enumerate() {
            *wi = u64::from_le_bytes(ct[i * 8..i * 8 + 8].try_into().unwrap());
        }
        w
    }

    /// Build a SampleInBall circuit, couple each coefficient output to a preloaded
    /// `want` inout (the coupling trick), and report whether the witness populates.
    fn check_sib(ct: &[u8; 48], expected: &[u64; N]) -> bool {
        let b = CircuitBuilder::new();
        let consts = FieldConsts::new(&b);
        let ct_wires: Vec<Wire> = (0..6).map(|_| b.add_inout()).collect();
        let out = sample_in_ball(&b, &consts, &ct_wires);
        let want: Vec<Wire> = (0..N).map(|_| b.add_inout()).collect();
        for (o, w) in out.iter().zip(&want) {
            b.assert_eq("coeff_eq", *o, *w);
        }
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        for (wire, val) in ct_wires.iter().zip(pack_ctilde(ct)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, val) in want.iter().zip(expected.iter()) {
            w[*wire] = Word::from_u64(*val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    #[test]
    fn sample_in_ball_matches_reference() {
        let mut rng = StdRng::seed_from_u64(202);
        for _ in 0..8 {
            let mut ct = [0u8; 48];
            rng.fill_bytes(&mut ct);
            let want = ref_sample_in_ball(&ct);
            // Sanity on the reference: exactly τ nonzero, all ∈ {1, q−1}.
            let nz = want.iter().filter(|&&x| x != 0).count();
            assert_eq!(nz, TAU, "reference must yield τ nonzero coefficients");
            assert!(want.iter().all(|&x| x == 0 || x == 1 || x == Q - 1));
            assert!(check_sib(&ct, &want), "sample_in_ball mismatch");
        }
    }

    /// A wrong expected coefficient must make the witness unsatisfiable — guards the
    /// coupling against vacuous success.
    #[test]
    fn sample_in_ball_rejects_wrong_output() {
        let ct = [5u8; 48];
        let mut want = ref_sample_in_ball(&ct);
        assert!(check_sib(&ct, &want));
        // Find a nonzero coefficient and corrupt it.
        let pos = want.iter().position(|&x| x != 0).unwrap();
        want[pos] = if want[pos] == 1 { Q - 1 } else { 1 };
        assert!(!check_sib(&ct, &want), "sign flip must be rejected");
    }

    /// Distinct c̃ must give distinct challenge polynomials, each matching its own
    /// reference — catches a sign/index desync.
    #[test]
    fn sample_in_ball_input_dependent() {
        let a = ref_sample_in_ball(&[1u8; 48]);
        let d = ref_sample_in_ball(&[2u8; 48]);
        assert_ne!(a, d);
        assert!(check_sib(&[1u8; 48], &a));
        assert!(check_sib(&[2u8; 48], &d));
    }
}

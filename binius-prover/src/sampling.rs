//! Rejection sampling for `ExpandA` (SPEC.md §3a, milestone M4).
//!
//! `Â = ExpandA(ρ)` is sampled **directly in the NTT domain** (FIPS-204 Alg. 32 /
//! `ml-dsa/src/sampling.rs:97` `RejNTTPoly`). For each matrix entry `Â[r][s]` the
//! reference absorbs `ρ ∥ s ∥ r` into SHAKE128, squeezes a fixed 840-byte buffer
//! (5 Keccak-f permutations = 280 three-byte candidates), maps each candidate to
//! `z = ((b₂ & 0x7F) << 16) | (b₁ << 8) | b₀` and keeps it iff `z < q`. The first
//! 256 accepted candidates are the polynomial's coefficients.
//!
//! A circuit cannot branch on the data-dependent rejection, so — exactly as SPEC.md
//! §3a prescribes — we mirror the reference's **fixed over-sampling**: squeeze the
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
//! the one documented, corpus-unobservable divergence (SPEC.md §3a, Corrections).

#![allow(dead_code)]

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Hint, Wire};

use crate::field::Q;

/// Degree of every polynomial: 256 coefficients.
pub const N: usize = 256;

/// Fixed ExpandA squeeze: 840 bytes = 5 SHAKE128 rate blocks = 280 candidates.
pub const EXPAND_A_BYTES: usize = 840;

/// Number of three-byte rejection-sampling candidates in the 840-byte buffer.
pub const N_CANDIDATES: usize = EXPAND_A_BYTES / 3; // 280

/// Self-populating advice for the ExpandA compaction (SPEC.md §3a). Given one
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
    // *is* both the rejection test and the coefficient range-check (SPEC.md §3a).
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

    // One group per candidate: [accept, rank, z]. Built once, shared across slots.
    let groups: Vec<[Wire; 3]> = (0..N_CANDIDATES)
        .map(|c| [accept[c], rank[c], z[c]])
        .collect();
    let refs: Vec<&[Wire]> = groups.iter().map(|g| g.as_slice()).collect();

    (0..N)
        .map(|k| {
            let sel = src[k];
            let picked = binius_circuits::multiplexer::multi_wire_multiplex(b, &refs, sel);
            let (a_sel, rank_sel, z_sel) = (picked[0], picked[1], picked[2]);
            // The selected candidate must be accepted and have prefix rank exactly k;
            // together these identify the unique k-th accepted candidate, pinning z.
            b.assert_eq("expandA_routed_accept", a_sel, one);
            b.assert_eq("expandA_routed_rank", rank_sel, b.add_constant_64(k as u64));
            z_sel
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake128;

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
}

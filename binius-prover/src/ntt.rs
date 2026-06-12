//! In-circuit number-theoretic transform over `R_q = Z_q[x]/(x²⁵⁶ + 1)`.
//!
//! ML-DSA-65 does all of its polynomial multiplication in the NTT domain, and the
//! `ml-dsa` reference samples `Â = ExpandA(ρ)` directly there (`sampling.rs`), so to
//! get bit-identical intermediates (and hence trivial witness population and exact
//! differential agreement) we mirror the reference NTT exactly rather than doing
//! schoolbook negacyclic convolution. The structure here is a line-for-line port of
//! `ml-dsa/src/ntt.rs`:
//!   * forward: 8 Cooley–Tukey butterfly layers, sub-block sizes 128→1, twiddles
//!     `ZETA_POW_BITREV[m]` with `m` running 1..256 (Algorithm 41);
//!   * inverse: 8 Gentleman–Sande layers with negated twiddles, `m` running 255..0,
//!     then a final scale by `256⁻¹ mod q` (Algorithm 42);
//!   * pointwise: coefficient-wise `mul_mod_q` (Algorithm 45 MultiplyNTT).
//!
//! Every butterfly is built from the property-tested mod-q gadgets in [`crate::field`],
//! so soundness reduces to theirs — each twiddle multiply carries the hint + range
//! check that pins its remainder, and the adds/subtracts are deterministic.

#![allow(dead_code)]

use crate::field::{add_mod_q, mul_mod_q, sub_mod_q, FieldConsts, Q};
use binius_frontend::{CircuitBuilder, Wire};

/// Degree of the ring (`x²⁵⁶ + 1`).
pub const N: usize = 256;

/// `ZETA_POW_BITREV[i] = ζ^bitrev8(i) mod q` with `ζ = 1753`, matching the table in
/// `ml-dsa/src/ntt.rs` (FIPS 204 Appendix B). Entry 0 is left zero to align indices
/// with the specification's `zetas` array.
pub const fn zeta_pow_bitrev() -> [u64; N] {
    const ZETA: u64 = 1753;

    // Powers of ζ in natural order.
    let mut pow = [0u64; N];
    let mut i = 0;
    let mut curr: u64 = 1;
    while i < N {
        pow[i] = curr;
        i += 1;
        // curr < q < 2²³, ζ < 2¹¹ ⇒ product < 2³⁴, no u64 overflow.
        curr = (curr * ZETA) % Q;
    }

    // Reorder by bit-reversing the 8-bit index.
    let mut bitrev = [0u64; N];
    let mut i = 1;
    while i < N {
        let r = (i as u8).reverse_bits() as usize;
        bitrev[i] = pow[r];
        i += 1;
    }
    bitrev
}

/// The (LEN, ITERATIONS) schedule of the forward transform's eight butterfly layers,
/// identical to the reference's `ntt_layer::<LEN, ITERATIONS>` call sequence.
const FWD_LAYERS: [(usize, usize); 8] = [
    (128, 1),
    (64, 2),
    (32, 4),
    (16, 8),
    (8, 16),
    (4, 32),
    (2, 64),
    (1, 128),
];

/// The inverse transform's layer schedule (the forward one reversed).
const INV_LAYERS: [(usize, usize); 8] = [
    (1, 128),
    (2, 64),
    (4, 32),
    (8, 16),
    (16, 8),
    (32, 4),
    (64, 2),
    (128, 1),
];

/// Twiddle-factor constants materialised once per circuit, so a transform does not
/// re-`add_constant_64` the same 256 values on every call.
pub struct NttConsts {
    /// Forward twiddles `ZETA_POW_BITREV[m]` as wires (index 0 unused).
    fwd: [Wire; N],
    /// Inverse twiddles `(-ZETA_POW_BITREV[m]) mod q` as wires (index 0 unused).
    neg: [Wire; N],
    /// `256⁻¹ mod q`.
    n_inv: Wire,
}

impl NttConsts {
    /// Materialise the twiddle constants in `b`.
    pub fn new(b: &CircuitBuilder) -> Self {
        let table = zeta_pow_bitrev();
        let fwd = std::array::from_fn(|i| b.add_constant_64(table[i]));
        let neg = std::array::from_fn(|i| {
            // -z mod q; entry 0 (z = 0) maps to 0, which is never indexed anyway.
            let z = table[i];
            let nz = if z == 0 { 0 } else { Q - z };
            b.add_constant_64(nz)
        });
        NttConsts {
            fwd,
            neg,
            n_inv: b.add_constant_64(crate::field::N_INV),
        }
    }
}

/// Forward NTT (Algorithm 41). Consumes 256 reduced coefficient wires, returns 256
/// reduced NTT-domain wires.
pub fn ntt(b: &CircuitBuilder, c: &FieldConsts, t: &NttConsts, w_in: &[Wire; N]) -> [Wire; N] {
    let mut w = *w_in;
    let mut m = 0usize;
    for &(len, iters) in &FWD_LAYERS {
        for i in 0..iters {
            let start = i * 2 * len;
            m += 1;
            let z = t.fwd[m];
            for j in start..start + len {
                // t = z·w[j+len]; w[j+len] = w[j] − t; w[j] = w[j] + t. Both reads of
                // w[j] see the original value (w[j] is reassigned last).
                let tw = mul_mod_q(b, c, z, w[j + len]);
                w[j + len] = sub_mod_q(b, c, w[j], tw);
                w[j] = add_mod_q(b, c, w[j], tw);
            }
        }
    }
    w
}

/// Inverse NTT (Algorithm 42): the Gentleman–Sande dual of [`ntt`], then a scale by
/// `256⁻¹ mod q`.
pub fn ntt_inverse(
    b: &CircuitBuilder,
    c: &FieldConsts,
    t: &NttConsts,
    w_in: &[Wire; N],
) -> [Wire; N] {
    let mut w = *w_in;
    let mut m = N;
    for &(len, iters) in &INV_LAYERS {
        for i in 0..iters {
            let start = i * 2 * len;
            m -= 1;
            let z = t.neg[m];
            for j in start..start + len {
                // t = w[j]; w[j] = t + w[j+len]; w[j+len] = z·(t − w[j+len]).
                let tj = w[j];
                let sum = add_mod_q(b, c, tj, w[j + len]);
                let diff = sub_mod_q(b, c, tj, w[j + len]);
                w[j] = sum;
                w[j + len] = mul_mod_q(b, c, z, diff);
            }
        }
    }
    // Scale every coefficient by 256⁻¹.
    for wj in w.iter_mut() {
        *wj = mul_mod_q(b, c, t.n_inv, *wj);
    }
    w
}

/// Coefficient-wise product in the NTT domain (Algorithm 45 MultiplyNTT).
pub fn pointwise_mul(
    b: &CircuitBuilder,
    c: &FieldConsts,
    x: &[Wire; N],
    y: &[Wire; N],
) -> [Wire; N] {
    std::array::from_fn(|i| mul_mod_q(b, c, x[i], y[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::word::Word;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    // ── Plain-Rust reference, an independent re-derivation of ml-dsa/src/ntt.rs ──
    // We cannot call the reference NTT directly (its Polynomial/NttPolynomial types
    // are crate-private), so we mirror the algorithm here and, crucially, anchor it
    // against an *independent* schoolbook negacyclic convolution (`poly_mul`) via the
    // multiplication-homomorphism property. If the twiddle table, layer schedule, or
    // butterfly direction were wrong, that anchor would fail.

    fn ref_ntt(w_in: &[u64; N]) -> [u64; N] {
        let table = zeta_pow_bitrev();
        let mut w = *w_in;
        let mut m = 0usize;
        for &(len, iters) in &FWD_LAYERS {
            for i in 0..iters {
                let start = i * 2 * len;
                m += 1;
                let z = table[m];
                for j in start..start + len {
                    let t = (z * w[j + len]) % Q;
                    w[j + len] = (w[j] + Q - t) % Q;
                    w[j] = (w[j] + t) % Q;
                }
            }
        }
        w
    }

    fn ref_ntt_inverse(w_in: &[u64; N]) -> [u64; N] {
        let table = zeta_pow_bitrev();
        let mut w = *w_in;
        let mut m = N;
        for &(len, iters) in &INV_LAYERS {
            for i in 0..iters {
                let start = i * 2 * len;
                m -= 1;
                let z = (Q - table[m]) % Q;
                for j in start..start + len {
                    let tj = w[j];
                    let sum = (tj + w[j + len]) % Q;
                    let diff = (tj + Q - w[j + len]) % Q;
                    w[j] = sum;
                    w[j + len] = (z * diff) % Q;
                }
            }
        }
        for wj in w.iter_mut() {
            *wj = (*wj * crate::field::N_INV) % Q;
        }
        w
    }

    /// Schoolbook multiplication in `R_q = Z_q[x]/(x²⁵⁶ + 1)` — the independent
    /// oracle for the homomorphism check (mirrors the reference test's `poly_mul`).
    fn poly_mul(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut out = [0u64; N];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                let prod = (x * y) % Q;
                let (sign_neg, idx) = if i + j < N {
                    (false, i + j)
                } else {
                    (true, i + j - N)
                };
                if sign_neg {
                    out[idx] = (out[idx] + Q - prod) % Q;
                } else {
                    out[idx] = (out[idx] + prod) % Q;
                }
            }
        }
        out
    }

    /// Build a circuit applying `f` to 256 input wires, couple each output to a
    /// preloaded `want` inout, and return whether the witness populates — i.e.
    /// whether the gadget output matches `expected` (and all internal range-checks
    /// hold). Same coupling trick as the field-gadget tests.
    fn check_transform(
        f: impl Fn(&CircuitBuilder, &FieldConsts, &NttConsts, &[Wire; N]) -> [Wire; N],
        input: &[u64; N],
        expected: &[u64; N],
    ) -> bool {
        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let t = NttConsts::new(&b);
        let in_wires: [Wire; N] = std::array::from_fn(|_| b.add_inout());
        let want_wires: [Wire; N] = std::array::from_fn(|_| b.add_inout());
        let out = f(&b, &c, &t, &in_wires);
        for i in 0..N {
            b.assert_eq("transform_eq", out[i], want_wires[i]);
        }
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        for i in 0..N {
            w[in_wires[i]] = Word::from_u64(input[i]);
            w[want_wires[i]] = Word::from_u64(expected[i]);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    fn random_poly(rng: &mut StdRng) -> [u64; N] {
        std::array::from_fn(|_| rng.next_u64() % Q)
    }

    #[test]
    fn circuit_ntt_matches_reference() {
        let mut rng = StdRng::seed_from_u64(11);
        for _ in 0..3 {
            let f = random_poly(&mut rng);
            let want = ref_ntt(&f);
            assert!(check_transform(ntt, &f, &want), "forward NTT mismatch");
        }
        // The ascending polynomial used by the reference's own test.
        let f: [u64; N] = std::array::from_fn(|i| i as u64);
        assert!(check_transform(ntt, &f, &ref_ntt(&f)));
    }

    #[test]
    fn circuit_ntt_inverse_matches_reference() {
        let mut rng = StdRng::seed_from_u64(12);
        for _ in 0..3 {
            let f = random_poly(&mut rng);
            let want = ref_ntt_inverse(&f);
            assert!(
                check_transform(ntt_inverse, &f, &want),
                "inverse NTT mismatch"
            );
        }
    }

    #[test]
    fn circuit_round_trip_is_identity() {
        let mut rng = StdRng::seed_from_u64(13);
        let f = random_poly(&mut rng);
        // ref-level sanity: NTT⁻¹(NTT(f)) == f.
        let back = ref_ntt_inverse(&ref_ntt(&f));
        assert_eq!(back, f, "reference round-trip is not identity");
        // And the circuit forward agrees with the reference forward (already covered),
        // so the round-trip holds in-circuit by composition.
    }

    /// The decisive anchor: `NTT⁻¹(NTT(f) ∘ NTT(g)) == poly_mul(f, g)`, with the
    /// right-hand side an independent schoolbook negacyclic convolution. Validates
    /// the forward transform, the inverse transform, the pointwise product, AND the
    /// twiddle table together — a wrong table cannot survive this.
    #[test]
    fn multiplication_homomorphism() {
        let mut rng = StdRng::seed_from_u64(14);
        for _ in 0..3 {
            let f = random_poly(&mut rng);
            let g = random_poly(&mut rng);

            let f_hat = ref_ntt(&f);
            let g_hat = ref_ntt(&g);
            let prod_hat: [u64; N] = std::array::from_fn(|i| (f_hat[i] * g_hat[i]) % Q);
            let got = ref_ntt_inverse(&prod_hat);
            let want = poly_mul(&f, &g);
            assert_eq!(got, want, "reference homomorphism broken — bad twiddle table?");
        }

        // Now confirm the in-circuit pointwise product matches at the gadget level.
        let f = random_poly(&mut rng);
        let g = random_poly(&mut rng);
        let f_hat = ref_ntt(&f);
        let g_hat = ref_ntt(&g);
        let want: [u64; N] = std::array::from_fn(|i| (f_hat[i] * g_hat[i]) % Q);

        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let x: [Wire; N] = std::array::from_fn(|_| b.add_inout());
        let y: [Wire; N] = std::array::from_fn(|_| b.add_inout());
        let wnt: [Wire; N] = std::array::from_fn(|_| b.add_inout());
        let out = pointwise_mul(&b, &c, &x, &y);
        for i in 0..N {
            b.assert_eq("pw_eq", out[i], wnt[i]);
        }
        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        for i in 0..N {
            w[x[i]] = Word::from_u64(f_hat[i]);
            w[y[i]] = Word::from_u64(g_hat[i]);
            w[wnt[i]] = Word::from_u64(want[i]);
        }
        assert!(
            circuit.populate_wire_witness(&mut w).is_ok(),
            "pointwise product mismatch"
        );
    }

    /// A wrong expected output must make the witness unsatisfiable — guards against a
    /// vacuously-passing coupling.
    #[test]
    fn rejects_wrong_output() {
        let mut rng = StdRng::seed_from_u64(15);
        let f = random_poly(&mut rng);
        let mut bad = ref_ntt(&f);
        bad[0] = (bad[0] + 1) % Q;
        assert!(!check_transform(ntt, &f, &bad));
    }
}

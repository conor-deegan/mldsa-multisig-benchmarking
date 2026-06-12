//! Mod-q field arithmetic gadgets for ML-DSA-65.
//!
//! ML-DSA-65 works in `Z_q` with `q = 2²³ − 2¹³ + 1 = 8380417`, a 23-bit prime.
//! Crucially `q` is **single-word**: every residue, every product (`< q² < 2⁴⁶`)
//! and every quotient (`< q`) fits in one 64-bit `Wire`, so we need none of the
//! `binius_circuits::bignum` machinery the 256-bit ECDSA case (`ethsign`) uses.
//!
//! The convention throughout: a "reduced" wire holds a value in `[0, q)`. The
//! gadgets here take reduced inputs and return reduced outputs, so they compose.
//! [`mul_mod_q`] is the only one that introduces a nondeterministic (hinted)
//! value — its quotient/remainder — and it range-checks both, which is the whole
//! difference between a sound circuit and a worthless one.

// These gadgets are the foundation the NTT/decode/verify layers build on;
// until those land some items are only exercised by this module's own tests.
#![allow(dead_code)]

use binius_frontend::{CircuitBuilder, Wire};

/// The ML-DSA-65 modulus `q = 2²³ − 2¹³ + 1`.
pub const Q: u64 = 8_380_417;

/// `256⁻¹ mod q`, the NTT inverse-scaling constant. Kept here so the
/// field layer owns every q-dependent constant.
pub const N_INV: u64 = 8_347_681;

/// A bundle of the q-dependent circuit constants, materialised once per circuit so
/// the gadgets do not re-`add_constant_64` the same value on every call.
#[derive(Clone, Copy)]
pub struct FieldConsts {
    /// The modulus `q` as a wire.
    pub q: Wire,
    /// The constant `0`.
    pub zero: Wire,
}

impl FieldConsts {
    /// Materialise the field constants in `b`.
    pub fn new(b: &CircuitBuilder) -> Self {
        FieldConsts {
            q: b.add_constant_64(Q),
            zero: b.add_constant_64(0),
        }
    }
}

/// `(a · x) mod q` for reduced inputs `a, x ∈ [0, q)`.
///
/// Soundness: the integer product `p = a·x < q² < 2⁴⁶` lands wholly
/// in the low word of `imul`, so the high word must be zero. A divmod **hint**
/// advises `(k, r)` with `p = k·q + r`; we re-multiply `k·q` in-circuit, add `r`,
/// and assert it equals `p`. The remainder **and** quotient are range-checked
/// against `q` with a single `icmp_ult` each — comparison, not a lookup, because
/// binius64 ships no range gadget. With `r < q` and the integer identity pinned
/// (no 64-bit wrap, since every term is `< 2⁴⁶`), `r` is forced to be `p mod q`.
pub fn mul_mod_q(b: &CircuitBuilder, c: &FieldConsts, a: Wire, x: Wire) -> Wire {
    // p = a·x. With 23-bit inputs the product is < 2⁴⁶, so hi must be 0.
    let (hi, lo) = b.imul(a, x);
    b.assert_zero("mulq_hi", hi);
    reduce_mod_q(b, c, lo)
}

/// Reduce any single-word value `p ∈ [0, 2⁶⁴)` (an `imul` low word, or a
/// lazy-reduction accumulator of several products) to `[0, q)`. Factored out of
/// [`mul_mod_q`] so the NTT layer can reduce a
/// sum-of-products once at the end of an accumulation rather than per term — for
/// the corpus such accumulators of ≤ L = 5 products stay `< 5q² < 2⁴⁹`.
///
/// Soundness rests on pinning the integer identity `p = k·q + r` with `0 ≤ r < q`,
/// which uniquely determines `r = p mod q`. Two facts make the in-circuit identity
/// hold over the integers rather than merely mod `2⁶⁴`:
///   * `assert_zero(kq_hi)` forces `k·q < 2⁶⁴`, so `kq_lo` is the true product;
///   * `assert_false(carry)` forces `kq_lo + r < 2⁶⁴` (no wrap), so `sum` is the
///     true sum.
/// We deliberately do **not** range-check `k < q`: the honest quotient `p div q`
/// can exceed `q` for a multi-product `p`, so such a check would reject honest
/// witnesses (a completeness break). `kq_hi == 0` already bounds `k·q`, and that —
/// together with `r < q` and the no-wrap carry check — is what soundness needs.
pub fn reduce_mod_q(b: &CircuitBuilder, c: &FieldConsts, p: Wire) -> Wire {
    // Hint: (k, r) with p = k·q + r, 0 ≤ r < q.
    let (quot, rem) = b.biguint_divide_hint(&[p], &[c.q]);
    let k = quot[0];
    let r = rem[0];

    // Re-derive k·q in-circuit; require it to fit one word so kq_lo is exact.
    let (kq_hi, kq_lo) = b.imul(k, c.q);
    b.assert_zero("reduceq_kq_hi", kq_hi);

    // k·q + r == p, pinned over the integers: the carry-out (cout's MSB) must be 0
    // so the in-word sum cannot wrap past 2⁶⁴ to forge a match.
    let (sum, carry) = b.iadd(kq_lo, r);
    b.assert_false("reduceq_no_wrap", carry);
    b.assert_eq("reduceq_identity", sum, p);

    // The crux of soundness: pin the remainder into [0, q). With the exact integer
    // identity above, this forces r = p mod q (and hence k = p div q).
    b.assert_true("reduceq_r_lt_q", b.icmp_ult(r, c.q));

    r
}

/// `(a + x) mod q` for reduced inputs. Deterministic: `s = a + x < 2q < 2²⁴` never
/// carries out of the word, then a single conditional subtract of `q` canonicalises
/// No hint, no range-check needed.
pub fn add_mod_q(b: &CircuitBuilder, c: &FieldConsts, a: Wire, x: Wire) -> Wire {
    let (s, _carry) = b.iadd(a, x);
    let ge = b.icmp_uge(s, c.q);
    let (s_minus_q, _bout) = b.isub_bin_bout(s, c.q, c.zero);
    b.select(ge, s_minus_q, s)
}

/// `(a − x) mod q` for reduced inputs. Deterministic: compute `a − x` (wrapping),
/// and when `a < x` add back `q` (the borrow wraps the `2⁶⁴` away, leaving
/// `a − x + q ∈ [1, q)`); otherwise keep `a − x ∈ [0, q)`.
pub fn sub_mod_q(b: &CircuitBuilder, c: &FieldConsts, a: Wire, x: Wire) -> Wire {
    let lt = b.icmp_ult(a, x);
    let (d, _bout) = b.isub_bin_bout(a, x, c.zero);
    let (d_plus_q, _carry) = b.iadd(d, c.q);
    b.select(lt, d_plus_q, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::word::Word;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// Whether the gadget `f` applied to `(a, x)` is satisfiable when its output is
    /// constrained to equal the independently-computed `expected`. This couples the
    /// gadget's output wire to a public `inout` we preload, so a correct gadget
    /// populates cleanly and a wrong one fails `populate_wire_witness` (the
    /// assert_eq, or one of the gadget's own range-checks, trips). Reading the wire
    /// back directly is avoided because `force_commit` on a fused gadget output is
    /// rejected by the gate-fusion pass.
    fn check2(
        f: impl Fn(&CircuitBuilder, &FieldConsts, Wire, Wire) -> Wire,
        a_val: u64,
        x_val: u64,
        expected: u64,
    ) -> bool {
        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let a = b.add_inout();
        let x = b.add_inout();
        let want = b.add_inout();
        let out = f(&b, &c, a, x);
        b.assert_eq("gadget_eq_expected", out, want);
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        w[a] = Word::from_u64(a_val);
        w[x] = Word::from_u64(x_val);
        w[want] = Word::from_u64(expected);
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    #[test]
    fn mul_mod_q_matches_reference() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..2000 {
            let a = rng.next_u64() % Q;
            let x = rng.next_u64() % Q;
            let want = ((a as u128 * x as u128) % Q as u128) as u64;
            assert!(check2(mul_mod_q, a, x, want), "mul_mod_q({a},{x})={want}");
        }
    }

    #[test]
    fn mul_mod_q_edge_cases() {
        for &(a, x) in &[(0, 0), (0, Q - 1), (Q - 1, Q - 1), (1, Q - 1), (Q - 1, 1)] {
            let want = ((a as u128 * x as u128) % Q as u128) as u64;
            assert!(check2(mul_mod_q, a, x, want), "mul_mod_q edge ({a},{x})");
        }
    }

    /// A wrong expected value must make the circuit unsatisfiable — confirms the
    /// equality coupling actually bites (i.e. the test cannot pass vacuously).
    #[test]
    fn mul_mod_q_rejects_wrong_output() {
        let want = ((123u128 * 456u128) % Q as u128) as u64;
        assert!(check2(mul_mod_q, 123, 456, want));
        assert!(!check2(mul_mod_q, 123, 456, want + 1));
    }

    /// Whether `reduce_mod_q(p)` is satisfiable when constrained to equal
    /// `expected`. Exercises the lazy-reduction path with `p` far above `q²`.
    fn check_reduce(p_val: u64, expected: u64) -> bool {
        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let p = b.add_inout();
        let want = b.add_inout();
        let out = reduce_mod_q(&b, &c, p);
        b.assert_eq("reduce_eq_expected", out, want);
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        w[p] = Word::from_u64(p_val);
        w[want] = Word::from_u64(expected);
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    /// reduce_mod_q must stay complete (and correct) for multi-product-sized
    /// accumulators — `p` up to ~2⁴⁹ (5·q²), where the honest quotient `p div q`
    /// is far larger than `q`. This is the lazy-reduction case the NTT layer needs.
    #[test]
    fn reduce_mod_q_handles_large_accumulators() {
        let mut rng = StdRng::seed_from_u64(7);
        // Single products, sums of a few products, and the extreme word.
        let bounds = [Q * Q, 5 * Q * Q, 1u64 << 49, u64::MAX];
        for &bound in &bounds {
            for _ in 0..500 {
                let p = rng.next_u64() % bound;
                assert!(check_reduce(p, p % Q), "reduce_mod_q({p}) bound={bound}");
            }
        }
        // And a wrong expected must be rejected.
        assert!(!check_reduce(5 * Q * Q, (5 * Q * Q) % Q + 1));
    }

    #[test]
    fn add_mod_q_matches_reference() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..2000 {
            let a = rng.next_u64() % Q;
            let x = rng.next_u64() % Q;
            assert!(check2(add_mod_q, a, x, (a + x) % Q), "add_mod_q({a},{x})");
        }
    }

    #[test]
    fn add_mod_q_edge_cases() {
        for &(a, x) in &[(0, 0), (Q - 1, Q - 1), (Q - 1, 1), (1, Q - 1), (0, Q - 1)] {
            assert!(
                check2(add_mod_q, a, x, (a + x) % Q),
                "add_mod_q edge ({a},{x})"
            );
        }
    }

    #[test]
    fn sub_mod_q_matches_reference() {
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..2000 {
            let a = rng.next_u64() % Q;
            let x = rng.next_u64() % Q;
            let want = (a + Q - x) % Q;
            assert!(check2(sub_mod_q, a, x, want), "sub_mod_q({a},{x})");
        }
    }

    #[test]
    fn sub_mod_q_edge_cases() {
        for &(a, x) in &[(0, 0), (0, Q - 1), (Q - 1, 0), (5, 5), (1, 2)] {
            let want = (a + Q - x) % Q;
            assert!(check2(sub_mod_q, a, x, want), "sub_mod_q edge ({a},{x})");
        }
    }
}

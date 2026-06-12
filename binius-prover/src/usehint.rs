//! `Decompose` + `UseHint` gadgets (FIPS 204 Alg. 36 / 40, milestone M4 step 7).
//!
//! Step 7 of the in-circuit verify (SPEC.md §4) turns the recomputed `wp`
//! coefficients into the high-bits string `w1 = UseHint(h, wp)` that is then
//! `Encode₄`'d and absorbed (with μ) into SHAKE256 to recompute `c̃′`. Both
//! gadgets here mirror `ml-dsa/src/hint.rs` (`use_hint`) and
//! `ml-dsa/src/algebra.rs` (`decompose`) coefficient-for-coefficient, so the
//! in-circuit `w1` is bit-identical to the reference's and the differential
//! agreement at M4 is exact.
//!
//! ## Soundness
//! [`decompose`] is the only place introducing a nondeterministic value — the
//! quotient/remainder of the division by `2γ2`. It range-checks the remainder
//! `< 2γ2` and pins the integer identity `r = q1·2γ2 + rem` exactly as
//! [`crate::field::reduce_mod_q`] pins `p = k·q + r`, so `(q1, rem)` are forced
//! to be the true Euclidean division (the reduced input `r ∈ [0, q)` makes
//! `q1 ≤ 15`, so the wrap-detecting carry/`hi` asserts suffice — no separate
//! quotient range-check is needed). Everything downstream (the centring select,
//! the edge-case wrap, all of `UseHint`) is pure combinational, so it adds no
//! further nondeterminism.

#![allow(dead_code)]

use binius_frontend::{CircuitBuilder, Wire};

use crate::field::{sub_mod_q, FieldConsts, Q};

/// `2γ2 = (q − 1) / 16 = 523776` for ML-DSA-65 (the low-bits modulus).
pub const TWO_GAMMA2: u64 = 523_776;

/// `γ2 = 261888` — the positive half-window for the centred low part `r0`.
pub const GAMMA2: u64 = 261_888;

/// `m = (q − 1) / 2γ2 = 16` — the number of high-bit buckets; `w1` coefficients
/// live in `[0, m)`. A power of two, so `mod m` is a `band` with `m − 1`.
pub const M: u64 = 16;

/// The decompose-specific circuit constants, materialised once per circuit.
#[derive(Clone, Copy)]
pub struct HintConsts {
    two_gamma2: Wire,
    gamma2: Wire,
    /// `q − 2γ2`, used to add the centred-negative offset without an `isub`.
    q_minus_2g2: Wire,
    /// `m = 16`, the edge-wrap comparison target.
    m: Wire,
    /// `m − 1 = 15`, the `mod m` mask.
    m_mask: Wire,
    one: Wire,
}

impl HintConsts {
    /// Materialise the decompose constants in `b`.
    pub fn new(b: &CircuitBuilder) -> Self {
        HintConsts {
            two_gamma2: b.add_constant_64(TWO_GAMMA2),
            gamma2: b.add_constant_64(GAMMA2),
            q_minus_2g2: b.add_constant_64(Q - TWO_GAMMA2),
            m: b.add_constant_64(M),
            m_mask: b.add_constant_64(M - 1),
            one: b.add_constant_64(1),
        }
    }
}

/// `Decompose(r)` (FIPS 204 Alg. 36) for a reduced input `r ∈ [0, q)`.
///
/// Returns `(r1, r0)` with `r1 ∈ [0, 16)` the high-bits bucket and `r0` the
/// centred low part stored mod q (`r0 ∈ [0, γ2] ∪ [q−γ2, q)`), satisfying
/// `r ≡ 2γ2·r1 + r0 (mod q)` exactly as the reference computes it (including the
/// `r1 = 0`, `r0 −= 1` edge case when `r − r0 = q − 1`).
pub fn decompose(b: &CircuitBuilder, c: &FieldConsts, h: &HintConsts, r: Wire) -> (Wire, Wire) {
    // Hint: r = q1·2γ2 + rem, 0 ≤ rem < 2γ2. With r < q < 2²³ both q1·2γ2 and the
    // sum stay well inside one word, so the identity holds over the integers once
    // the no-wrap asserts bite — forcing (q1, rem) to be the true division.
    let (quot, rem_v) = b.biguint_divide_hint(&[r], &[h.two_gamma2]);
    let q1 = quot[0];
    let rem = rem_v[0];

    let (qg_hi, qg_lo) = b.imul(q1, h.two_gamma2);
    b.assert_zero("decompose_qg_hi", qg_hi);
    let (sum, carry) = b.iadd(qg_lo, rem);
    b.assert_false("decompose_no_wrap", carry);
    b.assert_eq("decompose_identity", sum, r);
    // The soundness crux: pin the remainder into [0, 2γ2). With the exact integer
    // identity above, this forces rem = r mod 2γ2 (hence q1 = r div 2γ2).
    b.assert_true("decompose_rem_lt_2g2", b.icmp_ult(rem, h.two_gamma2));

    // Centre the remainder: rem ≤ γ2 stays positive; otherwise it becomes
    // rem − 2γ2, stored as rem + (q − 2γ2) ∈ [q−2γ2, q) (canonical, no wrap).
    let in_lower = b.icmp_ule(rem, h.gamma2);
    let (r0_neg, _c) = b.iadd(rem, h.q_minus_2g2);
    let r0_base = b.select(in_lower, rem, r0_neg);

    // High bucket: lower half keeps q1; upper half is q1 + 1 (which can reach 16).
    let (q1_plus1, _c2) = b.iadd(q1, h.one);
    let r1_base = b.select(in_lower, q1, q1_plus1);

    // Edge case (r − r0 = q − 1): the bucket would be 16, which never occurs
    // otherwise — either the upper half with q1 = 15, or r = q − 1 exactly where the
    // division yields q1 = 16. An equality test against m captures both, matching the
    // reference's `is_edge`. Wrap the bucket to 0 and decrement r0 by one *mod q*
    // (r0_base can be 0, e.g. at r = q − 1, where 0 − 1 must land on q − 1).
    let is_edge = b.icmp_eq(r1_base, h.m);
    let r1 = b.select(is_edge, c.zero, r1_base);
    let r0_dec = sub_mod_q(b, c, r0_base, h.one);
    let r0 = b.select(is_edge, r0_dec, r0_base);

    (r1, r0)
}

/// `UseHint(h, r)` (FIPS 204 Alg. 40), mirroring `ml-dsa/src/hint.rs::use_hint`.
///
/// `h_msb` is an MSB-boolean hint bit (the form [`crate::decode::decode_hint`]
/// emits). Returns the hint-adjusted high bits `∈ [0, 16)`: with `h = 0` the bare
/// bucket `r1`; with `h = 1`, `r1 ± 1 mod 16` according to the sign of the centred
/// low part `r0` (positive ⇔ `0 < r0 ≤ γ2`).
pub fn use_hint(
    b: &CircuitBuilder,
    c: &FieldConsts,
    h: &HintConsts,
    h_msb: Wire,
    r: Wire,
) -> Wire {
    let (r1, r0) = decompose(b, c, h, r);

    // r1 ± 1 mod 16 via band with 15 (r1 ∈ [0,15] ⇒ r1+1 ∈ [1,16], r1+15 ∈ [15,30],
    // and `& 15` realises the modular wrap exactly).
    let (r1p1, _) = b.iadd(r1, h.one);
    let r1_inc = b.band(r1p1, h.m_mask);
    let (r1p15, _) = b.iadd(r1, h.m_mask);
    let r1_dec = b.band(r1p15, h.m_mask);

    // r0 is "positive" ⇔ r0 ≠ 0 AND r0 ≤ γ2 (centred-negative values are stored as
    // q − x > γ2, so they fail the second test).
    let r0_nonzero = b.icmp_ne(r0, c.zero);
    let r0_le_g2 = b.icmp_ule(r0, h.gamma2);
    let r0_positive = b.band(r0_nonzero, r0_le_g2);

    let hinted = b.select(r0_positive, r1_inc, r1_dec);
    b.select(h_msb, hinted, r1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::word::Word;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    const Q32: u32 = 8_380_417;
    const TG2: u32 = 523_776;
    const G2: u32 = 261_888;
    const MM: u32 = 16;

    /// Independent plain-Rust `Decompose` straight off FIPS 204 Alg. 36 (the
    /// algorithm `ml-dsa`'s constant-time `decompose` implements). Returns
    /// `(r1, r0)` with `r0` in field representation.
    fn ref_decompose(r: u32) -> (u32, u32) {
        let raw = r % TG2;
        let r0 = if raw <= G2 {
            raw
        } else {
            (raw + Q32 - TG2) % Q32
        };
        let diff = (r + Q32 - r0) % Q32;
        if diff == Q32 - 1 {
            (0, (r0 + Q32 - 1) % Q32)
        } else {
            (diff / TG2, r0)
        }
    }

    /// Independent plain-Rust `UseHint` off FIPS 204 Alg. 40.
    fn ref_use_hint(h: bool, r: u32) -> u32 {
        let (r1, r0) = ref_decompose(r);
        let r1_inc = (r1 + 1) % MM;
        let r1_dec = (r1 + MM - 1) % MM;
        let r0_positive = r0 != 0 && r0 <= G2;
        let hinted = if r0_positive { r1_inc } else { r1_dec };
        if h {
            hinted
        } else {
            r1
        }
    }

    /// Whether `decompose(r)` is satisfiable when its outputs are constrained to
    /// equal the independently-computed `(r1, r0)`.
    fn check_decompose(r_val: u32, want_r1: u32, want_r0: u32) -> bool {
        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let h = HintConsts::new(&b);
        let r = b.add_inout();
        let w_r1 = b.add_inout();
        let w_r0 = b.add_inout();
        let (r1, r0) = decompose(&b, &c, &h, r);
        b.assert_eq("r1_eq", r1, w_r1);
        b.assert_eq("r0_eq", r0, w_r0);
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        w[r] = Word::from_u64(r_val as u64);
        w[w_r1] = Word::from_u64(want_r1 as u64);
        w[w_r0] = Word::from_u64(want_r0 as u64);
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    /// Whether `use_hint(h, r)` is satisfiable when its output equals `want`.
    fn check_use_hint(h_val: bool, r_val: u32, want: u32) -> bool {
        let b = CircuitBuilder::new();
        let c = FieldConsts::new(&b);
        let hc = HintConsts::new(&b);
        let h_in = b.add_inout();
        let r = b.add_inout();
        let want_w = b.add_inout();
        let out = use_hint(&b, &c, &hc, h_in, r);
        b.assert_eq("uh_eq", out, want_w);
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        // MSB-boolean hint bit: any wire with the MSB (un)set works.
        w[h_in] = Word::from_u64(if h_val { 1u64 << 63 } else { 0 });
        w[r] = Word::from_u64(r_val as u64);
        w[want_w] = Word::from_u64(want as u64);
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    #[test]
    fn decompose_matches_reference() {
        let mut rng = StdRng::seed_from_u64(101);
        for _ in 0..4000 {
            let r = (rng.next_u64() as u32) % Q32;
            let (r1, r0) = ref_decompose(r);
            assert!(check_decompose(r, r1, r0), "decompose({r}) = ({r1},{r0})");
        }
    }

    #[test]
    fn decompose_edge_and_boundaries() {
        // 0, q−1, exact bucket boundaries, the ±γ2 window edges, and the edge case
        // r − r0 = q − 1 (which occurs at the very top of the range).
        let mut rs = vec![0u32, 1, Q32 - 1, Q32 - 2, G2, G2 + 1, TG2 - 1, TG2, TG2 + 1];
        for k in 0..16u32 {
            rs.push(k * TG2);
            rs.push(k * TG2 + 1);
            rs.push(k * TG2 + G2);
            rs.push(k * TG2 + G2 + 1);
        }
        for &r in &rs {
            if r >= Q32 {
                continue;
            }
            let (r1, r0) = ref_decompose(r);
            assert!(check_decompose(r, r1, r0), "decompose edge ({r})");
        }
    }

    /// A wrong expected output must make the circuit unsatisfiable — confirms the
    /// equality coupling bites and the test cannot pass vacuously.
    #[test]
    fn decompose_rejects_wrong_output() {
        let r = 1_234_567u32;
        let (r1, r0) = ref_decompose(r);
        assert!(check_decompose(r, r1, r0));
        assert!(!check_decompose(r, (r1 + 1) % MM, r0));
        assert!(!check_decompose(r, r1, (r0 + 1) % Q32));
    }

    #[test]
    fn use_hint_matches_reference() {
        let mut rng = StdRng::seed_from_u64(202);
        for _ in 0..4000 {
            let r = (rng.next_u64() as u32) % Q32;
            let hbit = rng.next_u64() & 1 == 1;
            let want = ref_use_hint(hbit, r);
            assert!(check_use_hint(hbit, r, want), "use_hint({hbit},{r}) = {want}");
        }
    }

    #[test]
    fn use_hint_edge_and_boundaries() {
        let mut rs = vec![0u32, 1, Q32 - 1, Q32 - 2, G2, G2 + 1, Q32 - G2, Q32 - G2 - 1];
        for k in 0..16u32 {
            rs.push(k * TG2);
            rs.push(k * TG2 + 1);
            rs.push((k * TG2 + G2).min(Q32 - 1));
        }
        for &r in &rs {
            if r >= Q32 {
                continue;
            }
            for &hbit in &[false, true] {
                let want = ref_use_hint(hbit, r);
                assert!(check_use_hint(hbit, r, want), "use_hint edge ({hbit},{r})");
            }
        }
    }

    #[test]
    fn use_hint_rejects_wrong_output() {
        let r = 7_654_321u32;
        let want = ref_use_hint(true, r);
        assert!(check_use_hint(true, r, want));
        assert!(!check_use_hint(true, r, (want + 1) % MM));
    }
}

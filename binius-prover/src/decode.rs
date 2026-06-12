//! Byte ↔ coefficient decode/encode gadgets (SPEC.md §2, milestone M3b).
//!
//! ML-DSA's on-the-wire objects (the verifying key's `t1`, a signature's `z`, and
//! the recomputed `w1`) are bit-packed: each degree-256 polynomial stores its
//! coefficients as fixed-width little-endian bit fields, `SimpleBitPack` /
//! `BitPack` (FIPS 204 Alg. 16–17, `module_lattice::encoding::byte_encode`). This
//! module bridges those packed bytes — which arrive as `inout` wires, 8 bytes per
//! 64-bit word little-endian (see [`crate::shake`]) — to one-coefficient-per-wire
//! form for the field/NTT layers, and back again for `w1`.
//!
//! Crucially these are **pure combinational** functions of public input wires:
//! a `d`-bit field is carved out with constant `shr`/`shl`/`band`, so there is no
//! nondeterminism and hence nothing to range-check here — the soundness-critical
//! range-checks live in the mod-q reductions ([`crate::field`]) and the sampling
//! acceptance tests. The mask `(1 << d) − 1` already pins every decoded value into
//! `[0, 2^d)`, which for `t1` (`d = 10`) and `w1` (`d = 4`) is already a canonical
//! residue (`2^d < q`).

#![allow(dead_code)]

use binius_frontend::{CircuitBuilder, Wire};

use crate::field::{sub_mod_q, FieldConsts};

/// Number of coefficients in a degree-256 polynomial.
pub const N: usize = 256;

/// Maximum hint weight `ω = 55` for ML-DSA-65 — the number of index slots in the
/// encoded hint, hence the structural cap on the total number of set hint bits.
pub const OMEGA: usize = 55;

/// `K = 6` rows of the hint (one boolean polynomial per row of `A`).
pub const K: usize = 6;

/// `γ1 = 2¹⁹` — the centring constant for the signature's `z` (`BitPack` range
/// `[−(γ1−1), γ1]`, encoded as `d = 20`-bit fields of `γ1 − z`).
pub const GAMMA1: u64 = 1 << 19;

/// Extract the `d`-bit little-endian field starting at global bit `bit` from a slice
/// of words packed 8-bytes-per-word little-endian.
///
/// With words concatenated LSB-first, the packed byte stream's bit `g` lands at
/// `words[g / 64]` bit `g % 64`, so a `d ≤ 20`-bit coefficient spans at most two
/// adjacent words. All offsets are compile-time constants, so every `shr`/`shl` is
/// an immediate shift and the whole decode is a constant gate graph.
fn extract_field(b: &CircuitBuilder, words: &[Wire], bit: usize, d: u32, mask: Wire) -> Wire {
    let wo = bit / 64;
    let bo = (bit % 64) as u32;
    let raw = if bo + d <= 64 {
        // The field lies wholly within one word.
        b.shr(words[wo], bo)
    } else {
        // It straddles the boundary: low `64 − bo` bits from `words[wo]`, the rest
        // from the bottom of `words[wo + 1]` shifted up into place.
        let low = b.shr(words[wo], bo);
        let high = b.shl(words[wo + 1], 64 - bo);
        b.bor(low, high)
    };
    b.band(raw, mask)
}

/// `SimpleBitUnpack` over `d` bits: decode `words` (the packed encoding of one
/// polynomial, `32·d` bytes = `4·d` words) into 256 coefficient wires, each in
/// `[0, 2^d)`. Used for `t1` (`d = 10`); the result is a canonical residue because
/// `2^d < q`.
pub fn simple_bit_unpack(b: &CircuitBuilder, words: &[Wire], d: u32) -> Vec<Wire> {
    debug_assert_eq!(words.len(), 4 * d as usize, "expected 4·d words for one poly");
    let mask = b.add_constant_64((1u64 << d) - 1);
    (0..N)
        .map(|i| extract_field(b, words, i * d as usize, d, mask))
        .collect()
}

/// `BitUnpack` for the signature's `z` (`d = 20`, range `[−(γ1−1), γ1]`): decode the
/// 20-bit fields, then map each to its centred value `γ1 − x` reduced mod q
/// (FIPS 204 Alg. 17). `x ∈ [0, 2²⁰)` and `γ1 = 2¹⁹` are both `< q`, so the centred
/// coefficient is exactly `sub_mod_q(γ1, x)`.
///
/// No `‖z‖∞` norm check is emitted here — `raw_verify_mu` decides on `c̃` equality
/// alone, and a corrupted `z` perturbs `c̃′` (SPEC.md §4 Correction). A
/// norm-violating `z` is already dropped earlier by `Signature::decode` on the
/// reference path, so honest cases never exercise the out-of-range region.
pub fn bit_unpack_gamma1(b: &CircuitBuilder, c: &FieldConsts, words: &[Wire]) -> Vec<Wire> {
    debug_assert_eq!(words.len(), 80, "z encoding is 640 B = 80 words per poly");
    let mask = b.add_constant_64((1u64 << 20) - 1);
    let gamma1 = b.add_constant_64(GAMMA1);
    (0..N)
        .map(|i| {
            let x = extract_field(b, words, i * 20, 20, mask);
            sub_mod_q(b, c, gamma1, x)
        })
        .collect()
}

/// `SimpleBitPack` over `d` bits: pack 256 coefficient wires (each assumed `< 2^d`)
/// back into `4·d` little-endian words. Used to re-encode `w1` (`d = 4`) into the
/// 768-byte string absorbed into SHAKE256 for `c̃′` (SPEC.md §4 item 8).
///
/// Each output word holds `64 / d` coefficients; coefficient `i` contributes its low
/// `d` bits at bit `i·d`. We mask each coefficient to `d` bits defensively (the
/// `UseHint` output is already in `[0, 2^d)`) so a malformed upstream value cannot
/// bleed into a neighbour, then OR the shifted fields together.
pub fn simple_bit_pack(b: &CircuitBuilder, coeffs: &[Wire], d: u32) -> Vec<Wire> {
    debug_assert_eq!(coeffs.len(), N, "SimpleBitPack expects 256 coefficients");
    debug_assert_eq!(64 % d, 0, "this packer assumes d divides 64 (d=4 for w1)");
    let mask = b.add_constant_64((1u64 << d) - 1);
    let per_word = 64 / d as usize;
    let n_words = N * d as usize / 64;
    (0..n_words)
        .map(|w| {
            let mut acc = b.add_constant_64(0);
            for t in 0..per_word {
                let coeff = b.band(coeffs[w * per_word + t], mask);
                let shifted = b.shl(coeff, (t as u32) * d);
                acc = b.bor(acc, shifted);
            }
            acc
        })
        .collect()
}

/// `Hint::bit_unpack` (FIPS 204 Alg. 21 / `ml-dsa/src/hint.rs:128`): decode the
/// encoded hint (`ω + K = 61` bytes) into `K × 256` MSB-boolean hint wires, while
/// emitting the encoding-**validity** constraints that make the circuit
/// unsatisfiable on a malformed hint — the in-circuit analogue of the reference
/// returning `None` (SPEC.md §4 item 1, Correction point 5).
///
/// `words` holds the hint region packed 8-bytes-per-word little-endian (≥ 8 words,
/// covering the 61 bytes); the first `ω` bytes are the index slots, the last `K`
/// are the cumulative per-row cut counts. Returns `h[i][j]` for row `i ∈ [0, K)`,
/// coefficient `j ∈ [0, 256)`: a wire whose **MSB** is `1` iff that hint bit is set
/// (the form `select`/`assert_*` consume directly — UseHint, M4).
///
/// The four validity rules mirror the reference exactly:
///  1. **cuts non-decreasing** — `cut[i-1] ≤ cut[i]`;
///  2. **max cut ≤ ω** — under (1) the maximum is `cut[K-1]`, so `cut[K-1] ≤ ω`;
///  3. **indices past the max cut are zero** — slots `t ≥ cut[K-1]` are unused;
///  4. **per-segment strictly increasing** — within each row's index segment
///     `[cut[i-1], cut[i])` consecutive indices strictly increase.
///
/// Every output is a pure combinational function of the public hint bytes (no
/// hints/nondeterminism), so the only soundness obligations are these structural
/// asserts; the hint-weight `≤ ω` bound lives entirely in rules 2–3 plus the fixed
/// `ω` slot count (SPEC.md §2: "this — not a separate verify step — is where the
/// hint-weight bound actually lives").
pub fn decode_hint(b: &CircuitBuilder, words: &[Wire]) -> Vec<Vec<Wire>> {
    assert!(words.len() >= 8, "hint region needs ≥ 8 words for its 61 bytes");
    let byte = |g: usize| b.extract_byte(words[g / 8], (g % 8) as u32);
    let idx: Vec<Wire> = (0..OMEGA).map(byte).collect();
    let cut: Vec<Wire> = (0..K).map(|i| byte(OMEGA + i)).collect();

    let zero = b.add_constant_64(0);
    let omega_c = b.add_constant_64(OMEGA as u64);
    // Under rule (1) the cuts are non-decreasing, so the maximum is the last one.
    let max_cut = cut[K - 1];

    // (1) cuts non-decreasing.
    for i in 1..K {
        b.assert_true("hint_cuts_monotonic", b.icmp_ule(cut[i - 1], cut[i]));
    }
    // (2) max cut ≤ ω (reference: reject when `max_cut > indices.len() = ω`).
    b.assert_true("hint_max_cut_le_omega", b.icmp_ule(max_cut, omega_c));
    // (3) every index slot at or beyond the max cut must be zero.
    let tconst: Vec<Wire> = (0..OMEGA).map(|t| b.add_constant_64(t as u64)).collect();
    for t in 0..OMEGA {
        let past = b.icmp_uge(tconst[t], max_cut);
        b.assert_eq_cond("hint_pad_zero", idx[t], zero, past);
    }
    // (4) per-segment strictly increasing. A consecutive pair (t, t+1) lies inside a
    // single row's segment iff t+1 is a real index (< max_cut) and is not the start
    // of a new segment (not equal to any cut value). For such pairs require
    // idx[t] < idx[t+1]; phrase it as "no violation" so `assert_false` reads the MSB.
    for t in 0..OMEGA - 1 {
        let t1 = tconst[t + 1];
        let in_region = b.icmp_ult(t1, max_cut);
        let mut boundary = b.icmp_eq(t1, cut[0]);
        for &c in &cut[1..] {
            let e = b.icmp_eq(t1, c);
            boundary = b.bor(boundary, e);
        }
        let intra = b.band(in_region, b.bnot(boundary));
        let increasing = b.icmp_ult(idx[t], idx[t + 1]);
        let bad = b.band(intra, b.bnot(increasing));
        b.assert_false("hint_strict_increasing", bad);
    }

    // Membership m[i][t] = (start_i ≤ t < end_i), with start_0 = 0, start_i =
    // cut[i-1], end_i = cut[i]. Each real slot lands in exactly one row; padding
    // slots (t ≥ max_cut) match no row, so rule-(3) zeros never reach the output.
    let membership: Vec<Vec<Wire>> = (0..K)
        .map(|i| {
            let start = if i == 0 { zero } else { cut[i - 1] };
            let end = cut[i];
            (0..OMEGA)
                .map(|t| {
                    let ge = b.icmp_ule(start, tconst[t]);
                    let lt = b.icmp_ult(tconst[t], end);
                    b.band(ge, lt)
                })
                .collect()
        })
        .collect();

    // eq[t][j] = (idx[t] == j), shared across the K rows.
    let jconst: Vec<Wire> = (0..N).map(|j| b.add_constant_64(j as u64)).collect();
    let eq: Vec<Vec<Wire>> = (0..OMEGA)
        .map(|t| (0..N).map(|j| b.icmp_eq(idx[t], jconst[j])).collect())
        .collect();

    // h[i][j] = OR over slots t of (t in row i AND idx[t] == j).
    (0..K)
        .map(|i| {
            (0..N)
                .map(|j| {
                    let mut acc = zero;
                    for t in 0..OMEGA {
                        let hit = b.band(membership[i][t], eq[t][j]);
                        acc = b.bor(acc, hit);
                    }
                    acc
                })
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Q;
    use binius_core::word::Word;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// Plain-Rust `SimpleBitUnpack`: read the packed byte stream as an LSB-first
    /// bitstream, `d` bits per coefficient. Mirrors `module_lattice::byte_decode`.
    fn ref_simple_unpack(bytes: &[u8], d: u32) -> Vec<u64> {
        (0..N)
            .map(|i| {
                let mut v = 0u64;
                for bit in 0..d as usize {
                    let g = i * d as usize + bit;
                    let bitval = (bytes[g / 8] >> (g % 8)) & 1;
                    v |= (bitval as u64) << bit;
                }
                v
            })
            .collect()
    }

    /// Plain-Rust `SimpleBitPack`: inverse of [`ref_simple_unpack`].
    fn ref_simple_pack(coeffs: &[u64], d: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; N * d as usize / 8];
        for (i, &c) in coeffs.iter().enumerate() {
            for bit in 0..d as usize {
                let g = i * d as usize + bit;
                if (c >> bit) & 1 == 1 {
                    bytes[g / 8] |= 1 << (g % 8);
                }
            }
        }
        bytes
    }

    /// Pack bytes 8-per-word little-endian, exactly as the `inout` message wires do.
    fn pack_le(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks(8)
            .map(|chunk| {
                let mut w = [0u8; 8];
                w[..chunk.len()].copy_from_slice(chunk);
                u64::from_le_bytes(w)
            })
            .collect()
    }

    /// Build a circuit that decodes `bytes` with `simple_bit_unpack` and couples each
    /// of the 256 outputs to a preloaded `want` inout; return whether it populates.
    fn check_unpack(bytes: &[u8], d: u32, want: &[u64]) -> bool {
        let b = CircuitBuilder::new();
        let n_words = bytes.len() / 8;
        let in_wires: Vec<Wire> = (0..n_words).map(|_| b.add_inout()).collect();
        let out = simple_bit_unpack(&b, &in_wires, d);
        let want_wires: Vec<Wire> = (0..N).map(|_| b.add_inout()).collect();
        for (o, w) in out.iter().zip(&want_wires) {
            b.assert_eq("unpack_eq", *o, *w);
        }
        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        for (wire, val) in in_wires.iter().zip(pack_le(bytes)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, &val) in want_wires.iter().zip(want) {
            w[*wire] = Word::from_u64(val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    /// FIPS 204 Alg. 16 known-answer vector from `ml-dsa`'s own `encode.rs` test:
    /// `d = 10`, the 10-byte group `00 04 20 c0 00 04 14 60 c0 01` decodes to the
    /// coefficient pattern `0,1,2,3,4,5,6,7` repeating. Anchors our decoder to FIPS.
    #[test]
    fn simple_unpack_known_answer_d10() {
        let group = [0x00u8, 0x04, 0x20, 0xc0, 0x00, 0x04, 0x14, 0x60, 0xc0, 0x01];
        let bytes: Vec<u8> = group.iter().cycle().take(320).copied().collect();
        let want: Vec<u64> = (0..N).map(|i| (i % 8) as u64).collect();
        assert_eq!(ref_simple_unpack(&bytes, 10), want, "reference decoder mismatch");
        assert!(check_unpack(&bytes, 10, &want), "in-circuit decode mismatch");
    }

    /// Random round trips for `d = 10` (t1), against the plain reference decoder.
    #[test]
    fn simple_unpack_random_d10() {
        let mut rng = StdRng::seed_from_u64(101);
        for _ in 0..50 {
            let coeffs: Vec<u64> = (0..N).map(|_| rng.next_u64() % (1 << 10)).collect();
            let bytes = ref_simple_pack(&coeffs, 10);
            assert!(check_unpack(&bytes, 10, &coeffs));
        }
    }

    /// A wrong expected coefficient must make the witness unsatisfiable.
    #[test]
    fn simple_unpack_rejects_wrong_output() {
        let mut rng = StdRng::seed_from_u64(102);
        let mut coeffs: Vec<u64> = (0..N).map(|_| rng.next_u64() % (1 << 10)).collect();
        let bytes = ref_simple_pack(&coeffs, 10);
        assert!(check_unpack(&bytes, 10, &coeffs));
        coeffs[200] ^= 1;
        assert!(!check_unpack(&bytes, 10, &coeffs));
    }

    /// `z` decode (`d = 20`): the centred value `γ1 − x` reduced mod q.
    #[test]
    fn bit_unpack_gamma1_matches_reference() {
        let mut rng = StdRng::seed_from_u64(103);
        for _ in 0..30 {
            // Honest `z` decode values are 20-bit fields; the centred result must
            // equal (γ1 − x) mod q for every x in the full 20-bit range.
            let xs: Vec<u64> = (0..N).map(|_| rng.next_u64() % (1 << 20)).collect();
            let bytes = ref_simple_pack(&xs, 20);
            let want: Vec<u64> = xs
                .iter()
                .map(|&x| (GAMMA1 + Q - x) % Q)
                .collect();

            let b = CircuitBuilder::new();
            let c = FieldConsts::new(&b);
            let n_words = bytes.len() / 8;
            let in_wires: Vec<Wire> = (0..n_words).map(|_| b.add_inout()).collect();
            let out = bit_unpack_gamma1(&b, &c, &in_wires);
            let want_wires: Vec<Wire> = (0..N).map(|_| b.add_inout()).collect();
            for (o, wv) in out.iter().zip(&want_wires) {
                b.assert_eq("z_eq", *o, *wv);
            }
            let circuit = b.build();
            let mut w = circuit.new_witness_filler();
            for (wire, val) in in_wires.iter().zip(pack_le(&bytes)) {
                w[*wire] = Word::from_u64(val);
            }
            for (wire, &val) in want_wires.iter().zip(&want) {
                w[*wire] = Word::from_u64(val);
            }
            assert!(circuit.populate_wire_witness(&mut w).is_ok());
        }
    }

    /// `w1` encode (`d = 4`): in-circuit `SimpleBitPack` must reproduce the reference
    /// byte string (checked at word granularity), and decode-after-encode round-trips.
    #[test]
    fn simple_bit_pack_d4_matches_reference() {
        let mut rng = StdRng::seed_from_u64(104);
        for _ in 0..50 {
            let coeffs: Vec<u64> = (0..N).map(|_| rng.next_u64() % 16).collect();
            let want_words = pack_le(&ref_simple_pack(&coeffs, 4));

            let b = CircuitBuilder::new();
            let coeff_wires: Vec<Wire> = (0..N).map(|_| b.add_inout()).collect();
            let out = simple_bit_pack(&b, &coeff_wires, 4);
            assert_eq!(out.len(), want_words.len());
            let want_wires: Vec<Wire> = (0..out.len()).map(|_| b.add_inout()).collect();
            for (o, wv) in out.iter().zip(&want_wires) {
                b.assert_eq("w1_eq", *o, *wv);
            }
            let circuit = b.build();
            let mut w = circuit.new_witness_filler();
            for (wire, &val) in coeff_wires.iter().zip(&coeffs) {
                w[*wire] = Word::from_u64(val);
            }
            for (wire, &val) in want_wires.iter().zip(&want_words) {
                w[*wire] = Word::from_u64(val);
            }
            assert!(circuit.populate_wire_witness(&mut w).is_ok());
        }
    }

    // ---- Hint decode (M3c) ----------------------------------------------------

    /// Plain-Rust `Hint::bit_pack` (`ml-dsa/src/hint.rs:109`): encode a `K × 256`
    /// boolean hint into 61 bytes (ω index slots ∥ K cumulative cut counts).
    fn ref_hint_pack(h: &[[bool; N]; K]) -> Vec<u8> {
        let mut y = vec![0u8; OMEGA + K];
        let mut index = 0usize;
        for (i, row) in h.iter().enumerate() {
            for (j, &set) in row.iter().enumerate() {
                if set {
                    y[index] = j as u8;
                    index += 1;
                }
            }
            y[OMEGA + i] = index as u8;
        }
        y
    }

    /// Plain-Rust `Hint::bit_unpack` (`ml-dsa/src/hint.rs:128`): the exact reference
    /// the circuit must agree with, returning `None` on a malformed encoding.
    fn ref_hint_unpack(y: &[u8]) -> Option<[[bool; N]; K]> {
        let indices = &y[..OMEGA];
        let cuts: Vec<usize> = y[OMEGA..OMEGA + K].iter().map(|&c| c as usize).collect();
        let max_cut = *cuts.iter().max().unwrap();
        if !cuts.windows(2).all(|w| w[0] <= w[1])
            || max_cut > OMEGA
            || indices[max_cut..].iter().copied().max().unwrap_or(0) > 0
        {
            return None;
        }
        let mut h = [[false; N]; K];
        let mut start = 0usize;
        for (i, &end) in cuts.iter().enumerate() {
            let seg = &indices[start..end];
            if !seg.windows(2).all(|w| w[0] < w[1]) {
                return None;
            }
            for &j in seg {
                h[i][j as usize] = true;
            }
            start = end;
        }
        Some(h)
    }

    /// Build a circuit that decodes the 61 hint bytes and, for a valid encoding,
    /// pins every output bit to its reference value via `assert_true`/`assert_false`
    /// (which read the MSB-boolean the gadget emits). Returns whether it populates —
    /// `true` ⇔ the encoding is in-circuit valid and all 6·256 bits matched.
    fn check_hint(bytes: &[u8], expect: Option<&[[bool; N]; K]>) -> bool {
        let b = CircuitBuilder::new();
        // 61 bytes occupy 8 words (last 3 bytes are unused padding).
        let in_wires: Vec<Wire> = (0..8).map(|_| b.add_inout()).collect();
        let h = decode_hint(&b, &in_wires);
        if let Some(exp) = expect {
            for (i, row) in exp.iter().enumerate() {
                for (j, &set) in row.iter().enumerate() {
                    if set {
                        b.assert_true("h_bit_set", h[i][j]);
                    } else {
                        b.assert_false("h_bit_clear", h[i][j]);
                    }
                }
            }
        }
        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        let mut padded = bytes.to_vec();
        padded.resize(64, 0);
        for (wire, val) in in_wires.iter().zip(pack_le(&padded)) {
            w[*wire] = Word::from_u64(val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    /// A hand-built known-answer: two bits in row 0, one in row 2, rows 1/3/4/5
    /// empty. Anchors the decoder to a concretely-checkable encoding.
    #[test]
    fn hint_decode_known_answer() {
        let mut h = [[false; N]; K];
        h[0][5] = true;
        h[0][200] = true;
        h[2][17] = true;
        let bytes = ref_hint_pack(&h);
        // index slots: 5, 200, 17 then zeros; cuts: [2,2,3,3,3,3].
        assert_eq!(&bytes[..3], &[5, 200, 17]);
        assert_eq!(&bytes[OMEGA..], &[2, 2, 3, 3, 3, 3]);
        assert_eq!(ref_hint_unpack(&bytes), Some(h));
        assert!(check_hint(&bytes, Some(&h)));
    }

    /// Random valid hints (varied per-row weights summing to ≤ ω) must decode to
    /// exactly the reference bit matrix.
    #[test]
    fn hint_decode_random_valid() {
        let mut rng = StdRng::seed_from_u64(105);
        for _ in 0..40 {
            // Choose a total weight ≤ ω, then scatter it across the K rows with
            // distinct, ascending positions per row (what bit_pack always produces).
            let total = (rng.next_u64() as usize) % (OMEGA + 1);
            let mut h = [[false; N]; K];
            let mut placed = 0;
            while placed < total {
                let i = (rng.next_u64() as usize) % K;
                let j = (rng.next_u64() as usize) % N;
                if !h[i][j] {
                    h[i][j] = true;
                    placed += 1;
                }
            }
            let bytes = ref_hint_pack(&h);
            assert_eq!(ref_hint_unpack(&bytes), Some(h), "reference self-check");
            assert!(check_hint(&bytes, Some(&h)), "circuit decode mismatch");
        }
    }

    /// A wrong expected bit must make the circuit unsatisfiable — proves the
    /// output coupling actually bites (no vacuous pass).
    #[test]
    fn hint_decode_rejects_wrong_output() {
        let mut h = [[false; N]; K];
        h[1][42] = true;
        let bytes = ref_hint_pack(&h);
        assert!(check_hint(&bytes, Some(&h)));
        // Flip one expected bit: the gadget's true output now contradicts the pin.
        let mut wrong = h;
        wrong[1][42] = false;
        wrong[1][43] = true;
        assert!(!check_hint(&bytes, Some(&wrong)));
    }

    /// Every malformed-encoding class the reference rejects with `None` must make
    /// the circuit unsatisfiable. We mutate a valid encoding into each illegal
    /// shape and confirm both the reference and the circuit reject it.
    #[test]
    fn hint_decode_rejects_malformed() {
        // A valid base: row 0 has indices 3,9; row 1 has index 4. cuts [2,3,3,3,3,3].
        let mut h = [[false; N]; K];
        h[0][3] = true;
        h[0][9] = true;
        h[1][4] = true;
        let base = ref_hint_pack(&h);
        assert!(ref_hint_unpack(&base).is_some());
        assert!(check_hint(&base, None), "valid base must populate");

        // (1) non-monotonic cuts: cuts[1] < cuts[0].
        let mut m = base.clone();
        m[OMEGA + 1] = 1; // was 3, now < cuts[0]=2
        assert!(ref_hint_unpack(&m).is_none());
        assert!(!check_hint(&m, None), "non-monotonic cuts must reject");

        // (2) max cut > ω.
        let mut m = base.clone();
        for c in &mut m[OMEGA..] {
            *c = (OMEGA + 1) as u8;
        }
        assert!(ref_hint_unpack(&m).is_none());
        assert!(!check_hint(&m, None), "max cut > ω must reject");

        // (3) nonzero index slot past the max cut (slot 5, max_cut = 3).
        let mut m = base.clone();
        m[5] = 7;
        assert!(ref_hint_unpack(&m).is_none());
        assert!(!check_hint(&m, None), "nonzero padding index must reject");

        // (4a) segment not strictly increasing (equal indices in row 0).
        let mut m = base.clone();
        m[1] = m[0]; // indices[0] == indices[1] within row 0's segment
        assert!(ref_hint_unpack(&m).is_none());
        assert!(!check_hint(&m, None), "equal segment indices must reject");

        // (4b) segment decreasing.
        let mut m = base.clone();
        m[0] = 20;
        m[1] = 9; // 20 > 9 within the same segment
        assert!(ref_hint_unpack(&m).is_none());
        assert!(!check_hint(&m, None), "decreasing segment indices must reject");
    }
}

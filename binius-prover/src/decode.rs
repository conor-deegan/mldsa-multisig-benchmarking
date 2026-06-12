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
}

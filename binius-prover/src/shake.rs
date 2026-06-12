//! SHAKE128 / SHAKE256 extendable-output functions, built in-crate on the
//! Keccak-f[1600] permutation.
//!
//! `binius_circuits` ships only a Keccak-256 gadget (Ethereum pad `0x01`, a fixed
//! 256-bit digest, no XOF squeeze), which is unusable for ML-DSA: ML-DSA hashes
//! with the FIPS 202 XOFs `G = SHAKE128` and `H = SHAKE256` (domain pad `0x1F`,
//! arbitrary-length squeeze). So we reuse the upstream
//! [`Permutation::keccak_f1600`] primitive and wrap our own sponge around it.
//!
//! Every absorb and squeeze length in ML-DSA-65 is known at circuit-construction
//! time (ρ is 32 B, μ is 64 B, the ExpandA squeeze is a fixed 840 B, …), so each
//! sponge unrolls to a fixed number of permutations with **no data-dependent
//! loop** — the message length and output length are compile-time parameters, not
//! witnessed values.
//!
//! Byte ↔ word convention matches the upstream Keccak gadget and the `sha3` crate:
//! 8 message bytes pack little-endian into one 64-bit `Wire`
//! (`u64::from_le_bytes`), and the squeezed output words unpack the same way.

#![allow(dead_code)]

use binius_circuits::keccak::permutation::Permutation;
use binius_frontend::{CircuitBuilder, Wire};

/// SHAKE128 rate in bytes (`1600 − 2·128` bits = 168 B = 21 words).
pub const SHAKE128_RATE_BYTES: usize = 168;
/// SHAKE256 rate in bytes (`1600 − 2·256` bits = 136 B = 17 words).
pub const SHAKE256_RATE_BYTES: usize = 136;

/// The FIPS 202 XOF domain-separation byte. NB: **not** the Keccak gadget's `0x01`
/// nor SHA3-256's `0x06`.
const XOF_PAD: u64 = 0x1F;

/// SHAKE128 (`G`): absorb `in_len_bytes` of `message` (packed 8 bytes/word, little
/// endian) and squeeze `out_len_bytes`, returned as `out_len_bytes.div_ceil(8)`
/// words (the final word's high bytes beyond `out_len_bytes` are squeeze output too,
/// and callers that need an exact byte count mask them off).
pub fn shake128(
    b: &CircuitBuilder,
    message: &[Wire],
    in_len_bytes: usize,
    out_len_bytes: usize,
) -> Vec<Wire> {
    sponge(b, SHAKE128_RATE_BYTES / 8, message, in_len_bytes, out_len_bytes)
}

/// SHAKE256 (`H`): the SHAKE128 sponge at the 136-byte rate (see [`shake128`]).
pub fn shake256(
    b: &CircuitBuilder,
    message: &[Wire],
    in_len_bytes: usize,
    out_len_bytes: usize,
) -> Vec<Wire> {
    sponge(b, SHAKE256_RATE_BYTES / 8, message, in_len_bytes, out_len_bytes)
}

/// The shared FIPS 202 sponge specialised to a compile-time rate, input length and
/// output length. Absorb XORs each rate block into the leading `rate_words` state
/// lanes and permutes; the `pad10*1` padding appends the XOF byte `0x1F`, zero-fills
/// to the rate boundary and sets `0x80` in the block's final byte; squeeze reads the
/// leading `rate_words` lanes, permuting again whenever more output is required.
///
/// The padding logic mirrors the upstream `keccak256` gadget exactly (same masking
/// of a partial final word, same `(len + 1).div_ceil(rate)` block count so a message
/// that fills the rate gets a fresh padding block), changing only the domain byte
/// from `0x01` to `0x1F`.
fn sponge(
    b: &CircuitBuilder,
    rate_words: usize,
    message: &[Wire],
    in_len_bytes: usize,
    out_len_bytes: usize,
) -> Vec<Wire> {
    let rate_bytes = rate_words * 8;
    assert_eq!(
        message.len(),
        in_len_bytes.div_ceil(8),
        "message wire count ({}) must equal in_len_bytes.div_ceil(8) ({})",
        message.len(),
        in_len_bytes.div_ceil(8)
    );

    let zero = b.add_constant_64(0);

    // ── Build the padded message: a whole number of rate blocks ───────────────
    let n_blocks = (in_len_bytes + 1).div_ceil(rate_bytes);
    let n_padded_words = n_blocks * rate_words;
    let mut padded: Vec<Wire> = Vec::with_capacity(n_padded_words);

    if in_len_bytes % 8 == 0 {
        // Message ends on a word boundary: all message words are whole, and the
        // `0x1F` pad byte starts the next word.
        padded.extend_from_slice(message);
        padded.push(b.add_constant_64(XOF_PAD));
    } else {
        // The last message word is partial: mask off its invalid high bytes and
        // splice the `0x1F` pad byte directly after the valid ones.
        padded.extend_from_slice(&message[..message.len() - 1]);
        let last = message.len() - 1;
        let byte_in_word = in_len_bytes % 8;
        let mask = (1u64 << (byte_in_word * 8)) - 1;
        let masked = b.band(message[last], b.add_constant_64(mask));
        let pad_byte = XOF_PAD << (byte_in_word * 8);
        padded.push(b.bxor(masked, b.add_constant_64(pad_byte)));
    }

    padded.resize(n_padded_words, zero);

    // Set `0x80` in the most-significant byte of the final rate block. When the
    // message fills all but the last byte, this XOR lands on the same byte as the
    // `0x1F` above, yielding `0x9F` — the standard collapsed `pad10*1`.
    let last_byte_mask = 0x80u64 << 56;
    let li = n_padded_words - 1;
    padded[li] = b.bxor(padded[li], b.add_constant_64(last_byte_mask));

    // ── Absorb ────────────────────────────────────────────────────────────────
    let mut state = [zero; 25];
    for block in padded.chunks(rate_words) {
        for (i, &word) in block.iter().enumerate() {
            state[i] = b.bxor(state[i], word);
        }
        Permutation::keccak_f1600(b, &mut state);
    }

    // ── Squeeze ───────────────────────────────────────────────────────────────
    let out_words = out_len_bytes.div_ceil(8);
    let mut out: Vec<Wire> = Vec::with_capacity(out_words);
    'squeeze: loop {
        for i in 0..rate_words {
            out.push(state[i]);
            if out.len() == out_words {
                break 'squeeze;
            }
        }
        // Need another rate block: permute and continue reading.
        Permutation::keccak_f1600(b, &mut state);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::word::Word;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{Shake128, Shake256};

    /// Pack `bytes` little-endian into `bytes.len().div_ceil(8)` u64 words (the
    /// final word zero-padded), exactly as the message wires expect.
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

    fn ref_shake128(msg: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = Shake128::default();
        h.update(msg);
        let mut r = h.finalize_xof();
        let mut out = vec![0u8; out_len];
        r.read(&mut out);
        out
    }

    fn ref_shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = Shake256::default();
        h.update(msg);
        let mut r = h.finalize_xof();
        let mut out = vec![0u8; out_len];
        r.read(&mut out);
        out
    }

    /// Build a circuit that hashes a fixed-length message and couples each output
    /// word to a preloaded `want` inout, returning whether the witness populates —
    /// i.e. whether the in-circuit sponge matches the `sha3` reference (and a wrong
    /// expectation is rejected). Same coupling trick as the field/NTT tests.
    fn check(
        which: u16,
        msg: &[u8],
        out_len: usize,
        expected: &[u8],
    ) -> bool {
        let b = CircuitBuilder::new();
        let in_words = msg.len().div_ceil(8);
        let msg_wires: Vec<Wire> = (0..in_words).map(|_| b.add_inout()).collect();
        let out = if which == 128 {
            shake128(&b, &msg_wires, msg.len(), out_len)
        } else {
            shake256(&b, &msg_wires, msg.len(), out_len)
        };
        let want_wires: Vec<Wire> = (0..out.len()).map(|_| b.add_inout()).collect();
        for (o, w) in out.iter().zip(&want_wires) {
            b.assert_eq("shake_eq", *o, *w);
        }
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        for (wire, val) in msg_wires.iter().zip(pack_le(msg)) {
            w[*wire] = Word::from_u64(val);
        }
        // Expected words: the reference output, zero-padded to the squeezed word
        // count (the high bytes of the last word are genuine squeeze output, which
        // we reproduce by reading `out.len()*8` bytes from the reference).
        let exp_full = if expected.len() < out.len() * 8 {
            let mut full = if which == 128 {
                ref_shake128(msg, out.len() * 8)
            } else {
                ref_shake256(msg, out.len() * 8)
            };
            full.truncate(out.len() * 8);
            full
        } else {
            expected.to_vec()
        };
        for (wire, val) in want_wires.iter().zip(pack_le(&exp_full)) {
            w[*wire] = Word::from_u64(val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    #[test]
    fn shake128_matches_reference() {
        let mut rng = StdRng::seed_from_u64(21);
        // Lengths straddling the 168-byte rate and word boundaries, plus the empty
        // message and the ML-DSA-relevant ExpandA squeeze (840 B = 5 blocks).
        for &in_len in &[0usize, 1, 7, 8, 9, 32, 167, 168, 169, 200] {
            for &out_len in &[1usize, 8, 32, 168, 169, 840] {
                let mut msg = vec![0u8; in_len];
                rng.fill_bytes(&mut msg);
                let want = ref_shake128(&msg, out_len);
                assert!(
                    check(128, &msg, out_len, &want),
                    "shake128 in={in_len} out={out_len}"
                );
            }
        }
    }

    #[test]
    fn shake256_matches_reference() {
        let mut rng = StdRng::seed_from_u64(22);
        // Straddle the 136-byte rate; 48/64 B are the c̃ and μ ML-DSA output sizes.
        for &in_len in &[0usize, 1, 7, 8, 64, 135, 136, 137, 300] {
            for &out_len in &[1usize, 32, 48, 64, 136, 137] {
                let mut msg = vec![0u8; in_len];
                rng.fill_bytes(&mut msg);
                let want = ref_shake256(&msg, out_len);
                assert!(
                    check(256, &msg, out_len, &want),
                    "shake256 in={in_len} out={out_len}"
                );
            }
        }
    }

    /// A wrong expected output must make the witness unsatisfiable — guards against
    /// a vacuously-passing coupling.
    #[test]
    fn rejects_wrong_output() {
        let msg = b"binius";
        let mut want = ref_shake256(msg, 32);
        assert!(check(256, msg, 32, &want));
        want[0] ^= 1;
        assert!(!check(256, msg, 32, &want));
    }

    /// SHAKE128 and SHAKE256 must genuinely differ (catches a rate/pad mix-up that
    /// would otherwise pass both reference comparisons by coincidence on short out).
    #[test]
    fn distinct_xofs() {
        let msg = b"domain separation";
        let a = ref_shake128(msg, 32);
        let c = ref_shake256(msg, 32);
        assert_ne!(a, c);
        assert!(check(128, msg, 32, &a));
        assert!(check(256, msg, 32, &c));
    }
}

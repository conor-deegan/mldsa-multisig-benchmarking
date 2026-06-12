//! Single-signature ML-DSA-65 verification, in-circuit.
//!
//! This module composes every lower-layer gadget (field, NTT, SHAKE, decode,
//! sampling, UseHint) into the exact `raw_verify_mu` relation the oracle is
//! differential against (`ml-dsa/src/verifying.rs:106`). The reference decides
//! **accept ⇔ c̃ = c̃′** and nothing else; so does this.
//!
//! [`recompute_ctilde`] takes the on-the-wire verifying-key bytes, the 64-byte
//! message and the signature bytes (all as little-endian-packed `Wire` words) and
//! returns the recomputed 48-byte challenge `c̃′` as 6 words. The N-of-M layer
//! couples each signature's `c̃′` to its decoded `c̃` with `assert_eq`; a mismatch
//! makes that subcircuit unsatisfiable, exactly the reference's per-signature
//! `false`.
//!
//! ## Byte layout consumed (all word-aligned, so slicing is exact)
//! * **vk** (1952 B = 244 words): ρ = words `[0,4)`; `t1[r]` = words
//!   `[4+40r, 4+40(r+1))` (each `SimpleBitPack₁₀`, 320 B = 40 words).
//! * **sig** (3309 B = 414 words): c̃ = words `[0,6)` (48 B); `z[l]` = words
//!   `[6+80l, 6+80(l+1))` (each `BitPack₂₀`, 640 B = 80 words); hint = words
//!   `[406, 414)` (61 B, the last 3 bytes of word 413 are padding).
//! * **msg** (64 B = 8 words).
//!
//! Every SHAKE absorb/squeeze length here is compile-time fixed, so the whole
//! chain unrolls to a constant gate graph — no nondeterminism beyond the mod-q
//! hints the field layer already range-checks.

#![allow(dead_code)]

use binius_frontend::{Circuit, CircuitBuilder, Wire};

use crate::decode::{bit_unpack_gamma1, decode_hint, simple_bit_pack, simple_bit_unpack, K};
use crate::field::FieldConsts;
use crate::ntt::{ntt, ntt_inverse, pointwise_mul, NttConsts, N};
use crate::sampling::{rej_ntt_poly, sample_in_ball};
use crate::shake::shake256;
use crate::usehint::{use_hint, HintConsts};

/// Number of columns of `A` (length of the `z` vector) for ML-DSA-65.
pub const L: usize = 5;

/// Words in a verifying-key encoding (1952 B).
pub const VK_WORDS: usize = 1952 / 8; // 244
/// Words in a signature encoding (3309 B, last word zero-padded).
pub const SIG_WORDS: usize = 3309_usize.div_ceil(8); // 414
/// Words in the 64-byte message.
pub const MSG_WORDS: usize = 8;

/// Add the per-coefficient products `Σ_s A[r][s] ∘ z_hat[s]` (mod q) into the
/// accumulator. Each `mul_mod_q` reduces its single product; the running sum is
/// kept reduced with `add_mod_q`, which is cheap (no hint) and keeps every term in
/// `[0, q)` for the next pointwise multiply.
fn matrix_vector_row(
    b: &CircuitBuilder,
    fc: &FieldConsts,
    a_row: &[[Wire; N]; L],
    z_hat: &[[Wire; N]; L],
) -> [Wire; N] {
    let mut acc = pointwise_mul(b, fc, &a_row[0], &z_hat[0]);
    for s in 1..L {
        let term = pointwise_mul(b, fc, &a_row[s], &z_hat[s]);
        for j in 0..N {
            acc[j] = crate::field::add_mod_q(b, fc, acc[j], term[j]);
        }
    }
    acc
}

/// Recompute `c̃′ = raw_verify_mu(vk, μ(msg), sig)` as 6 words (48 bytes).
///
/// `key_words` / `msg_words` / `sig_words` are the little-endian-packed encodings
/// (lengths [`VK_WORDS`] / [`MSG_WORDS`] / [`SIG_WORDS`]). The hint-decode validity
/// constraints are emitted as a side effect of `decode_hint`,
/// so a malformed hint makes the enclosing circuit unsatisfiable — the in-circuit
/// analogue of `Hint::bit_unpack` returning `None`.
pub fn recompute_ctilde(
    b: &CircuitBuilder,
    fc: &FieldConsts,
    nc: &NttConsts,
    hc: &HintConsts,
    key_words: &[Wire],
    msg_words: &[Wire],
    sig_words: &[Wire],
) -> [Wire; 6] {
    assert_eq!(key_words.len(), VK_WORDS, "vk is 1952 B = 244 words");
    assert_eq!(msg_words.len(), MSG_WORDS, "message is 64 B = 8 words");
    assert_eq!(sig_words.len(), SIG_WORDS, "sig is 3309 B = 414 words");

    // ── Decode vk: ρ and 2¹³·t1, NTT'd → t1_2d_hat[r] ──────────────────────────
    let rho = &key_words[0..4];
    let t1_2d_hat: Vec<[Wire; N]> = (0..K)
        .map(|r| {
            let words = &key_words[4 + 40 * r..4 + 40 * (r + 1)];
            let t1 = simple_bit_unpack(b, words, 10);
            // 2¹³·t1 with t1 < 2¹⁰ ⇒ product < 2²³ < q: no reduction, just a shift.
            let scaled: [Wire; N] = std::array::from_fn(|j| b.shl(t1[j], 13));
            ntt(b, fc, nc, &scaled)
        })
        .collect();

    // ── Decode sig: c̃, z[l] (→ ẑ[l]), hint ────────────────────────────────────
    let ctilde = &sig_words[0..6];
    let z_hat: [[Wire; N]; L] = std::array::from_fn(|l| {
        let words = &sig_words[6 + 80 * l..6 + 80 * (l + 1)];
        let z = bit_unpack_gamma1(b, fc, words);
        let z_arr: [Wire; N] = std::array::from_fn(|j| z[j]);
        ntt(b, fc, nc, &z_arr)
    });
    let hint_words = &sig_words[406..414];
    let hint = decode_hint(b, hint_words); // K × 256 MSB-bool, emits validity asserts

    // ── c = SampleInBall(c̃); ĉ = NTT(c) ───────────────────────────────────────
    let c = sample_in_ball(b, fc, ctilde);
    let c_arr: [Wire; N] = std::array::from_fn(|j| c[j]);
    let c_hat = ntt(b, fc, nc, &c_arr);

    // ── Â = ExpandA(ρ), in the NTT domain ──────────────────────────────────────
    // a_hat[r][s] are the K·L sampled polynomials.
    let a_hat: Vec<[[Wire; N]; L]> = (0..K)
        .map(|r| {
            std::array::from_fn(|s| {
                let poly = rej_ntt_poly(b, rho, r as u8, s as u8);
                std::array::from_fn(|j| poly[j])
            })
        })
        .collect();

    // ── wp[r] = NTT⁻¹(Âẑ[r] − ĉ·t1_2d_hat[r]); w1[r] = UseHint(h[r], wp[r]) ─────
    let mut w1_enc: Vec<Wire> = Vec::with_capacity(K * 16);
    for r in 0..K {
        let az = matrix_vector_row(b, fc, &a_hat[r], &z_hat);
        let ct1 = pointwise_mul(b, fc, &c_hat, &t1_2d_hat[r]);
        let diff: [Wire; N] =
            std::array::from_fn(|j| crate::field::sub_mod_q(b, fc, az[j], ct1[j]));
        let wp = ntt_inverse(b, fc, nc, &diff);

        let w1: Vec<Wire> = (0..N)
            .map(|j| use_hint(b, fc, hc, hint[r][j], wp[j]))
            .collect();
        // SimpleBitPack₄ → 16 words (128 B) per row.
        w1_enc.extend(simple_bit_pack(b, &w1, 4));
    }
    debug_assert_eq!(w1_enc.len(), K * 16, "w1 encoding is 768 B = 96 words");

    // ── tr = H(vkEncode)[..64]; μ = H(tr ∥ 0x00 ∥ 0x00 ∥ M)[..64] ──────────────
    let tr = shake256(b, key_words, 1952, 64); // 8 words

    // μ absorbs tr(64 B) ∥ 0x00 ∥ 0x00 ∥ M(64 B) = 130 B. The two domain bytes push
    // the message off the word boundary by 2 bytes, so re-pack the 130-byte stream:
    // words [0,8) are tr; word 8 is M[0..6] shifted up past the two zero bytes; each
    // later word splices the carried-over 2 high bytes of M[i-1] with M[i].
    let mut mu_in: Vec<Wire> = tr.clone();
    mu_in.push(b.shl(msg_words[0], 16));
    for i in 1..MSG_WORDS {
        let lo = b.shr(msg_words[i - 1], 48);
        let hi = b.shl(msg_words[i], 16);
        mu_in.push(b.bor(lo, hi));
    }
    // Final word: the trailing 2 bytes of M (positions 62,63) land in its low 2 bytes;
    // the rest is past the 130-byte length and masked off by the sponge padding.
    mu_in.push(b.shr(msg_words[MSG_WORDS - 1], 48));
    debug_assert_eq!(mu_in.len(), 130_usize.div_ceil(8));
    let mu = shake256(b, &mu_in, 130, 64); // 8 words

    // ── c̃′ = H(μ ∥ w1_enc)[..48] ───────────────────────────────────────────────
    let mut cp_in: Vec<Wire> = mu;
    cp_in.extend_from_slice(&w1_enc);
    debug_assert_eq!(cp_in.len(), 8 + K * 16, "μ ∥ w1_enc is 832 B = 104 words");
    let cp = shake256(b, &cp_in, 64 + 768, 48); // 6 words, exact

    std::array::from_fn(|i| cp[i])
}

/// A compiled single-signature ML-DSA-65 verify circuit, reusable across many
/// witnesses. The N-of-M layer builds this **once** and
/// populates it per `(key, msg, sig)` slot — peak memory stays at one single-sig
/// circuit regardless of `n` (building one giant `n`-signature circuit would
/// OOM at `n = 6`).
///
/// The lone constraint coupling is `c̃′ == sig.c̃` (the signature's own challenge,
/// `sig_wires[0..6]`): the witness populates iff the in-circuit `raw_verify_mu`
/// reproduces the stored challenge — i.e. iff the reference's per-signature
/// `key.verify(msg, sig)` (after a successful `Signature::decode`) would return
/// `Ok`. A malformed hint trips `decode_hint`'s validity asserts instead, the
/// in-circuit analogue of `Signature::try_from` dropping the signature.
pub struct SingleSig {
    /// The compiled circuit; `populate_wire_witness` is `Ok` iff this slot verifies.
    pub circuit: Circuit,
    /// `inout` words for the 1952-byte verifying key (ρ ∥ t1).
    pub key_wires: Vec<Wire>,
    /// `inout` words for the 64-byte message.
    pub msg_wires: Vec<Wire>,
    /// `witness` words for the 3309-byte signature (c̃ ∥ z ∥ h).
    pub sig_wires: Vec<Wire>,
}

/// Build the single-signature verify circuit and return it with its bound wires.
pub fn build_single_sig() -> SingleSig {
    let b = CircuitBuilder::new();
    let fc = FieldConsts::new(&b);
    let nc = NttConsts::new(&b);
    let hc = HintConsts::new(&b);

    let key_wires: Vec<Wire> = (0..VK_WORDS).map(|_| b.add_inout()).collect();
    let msg_wires: Vec<Wire> = (0..MSG_WORDS).map(|_| b.add_inout()).collect();
    let sig_wires: Vec<Wire> = (0..SIG_WORDS).map(|_| b.add_witness()).collect();

    let cp = recompute_ctilde(&b, &fc, &nc, &hc, &key_wires, &msg_wires, &sig_wires);
    // Couple c̃′ to the signature's own stored c̃ (sig_wires[0..6]); a mismatch — the
    // reference's per-signature reject — makes this witness unsatisfiable.
    for i in 0..6 {
        b.assert_eq("ctilde_eq", cp[i], sig_wires[i]);
    }

    let circuit = b.build();
    SingleSig {
        circuit,
        key_wires,
        msg_wires,
        sig_wires,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::NttConsts;
    use binius_core::word::Word;
    use ml_dsa::{KeyInit, MlDsa65, Verifier, VerifyingKey};
    use policy::Policy;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use signing::sign;

    /// Pack bytes 8-per-word little-endian, the `inout`/`witness` word convention.
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

    /// Build a circuit that recomputes c̃′ from a real (vk, msg, sig) and couples it
    /// to a preloaded `want` (the signature's own c̃). Returns whether the witness
    /// populates — `true` ⇔ the in-circuit verify reproduced the reference c̃ exactly.
    fn check(vk: &[u8], msg: &[u8], sig: &[u8], want_ctilde: &[u8]) -> bool {
        let b = CircuitBuilder::new();
        let fc = FieldConsts::new(&b);
        let nc = NttConsts::new(&b);
        let hc = HintConsts::new(&b);

        let key_wires: Vec<Wire> = (0..VK_WORDS).map(|_| b.add_inout()).collect();
        let msg_wires: Vec<Wire> = (0..MSG_WORDS).map(|_| b.add_inout()).collect();
        let sig_wires: Vec<Wire> = (0..SIG_WORDS).map(|_| b.add_witness()).collect();
        let want_wires: Vec<Wire> = (0..6).map(|_| b.add_inout()).collect();

        let cp = recompute_ctilde(&b, &fc, &nc, &hc, &key_wires, &msg_wires, &sig_wires);
        for i in 0..6 {
            b.assert_eq("ctilde_eq", cp[i], want_wires[i]);
        }
        let circuit = b.build();

        let mut w = circuit.new_witness_filler();
        for (wire, val) in key_wires.iter().zip(pack_le(vk)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, val) in msg_wires.iter().zip(pack_le(msg)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, val) in sig_wires.iter().zip(pack_le(sig)) {
            w[*wire] = Word::from_u64(val);
        }
        for (wire, val) in want_wires.iter().zip(pack_le(want_ctilde)) {
            w[*wire] = Word::from_u64(val);
        }
        circuit.populate_wire_witness(&mut w).is_ok()
    }

    /// The decisive end-to-end check: a genuine ML-DSA-65 signature must make the
    /// in-circuit `raw_verify_mu` reproduce its own c̃ (so c̃′ == c̃). This exercises
    /// the entire §4 chain on real data — decode, SampleInBall, NTT, ExpandA,
    /// pointwise, UseHint, w1 encode, μ/tr SHAKE256 and c̃′ — against the reference
    /// that produced the signature.
    #[test]
    fn verifies_real_signature() {
        let mut rng = StdRng::seed_from_u64(2024);
        let policy = Policy { n: 1, m: 1 };
        let mut msg = [0u8; 64];
        rng.fill_bytes(&mut msg);
        let signed = sign(&policy, &msg, &mut rng);
        let vk = signed.keys[0].encode().to_vec();
        let sig = signed.sigs[0].encode().to_vec();
        let ctilde = &sig[0..48];

        // Reference sanity: the signature genuinely verifies.
        assert!(
            VerifyingKey::<MlDsa65>::new_from_slice(&vk)
                .unwrap()
                .verify(&msg, &signed.sigs[0])
                .is_ok(),
            "reference must accept the honest signature"
        );

        assert!(
            check(&vk, &msg, &sig, ctilde),
            "in-circuit c̃′ did not match the signature's c̃"
        );
    }

    /// Measurement-only: build the full single-sig circuit and print its gate stats
    /// (no populate). Run with `--ignored --nocapture` to see the cost breakdown.
    #[test]
    #[ignore]
    fn measure_circuit_size() {
        use binius_frontend::stat::CircuitStat;
        let b = CircuitBuilder::new();
        let fc = FieldConsts::new(&b);
        let nc = NttConsts::new(&b);
        let hc = HintConsts::new(&b);
        let key_wires: Vec<Wire> = (0..VK_WORDS).map(|_| b.add_inout()).collect();
        let msg_wires: Vec<Wire> = (0..MSG_WORDS).map(|_| b.add_inout()).collect();
        let sig_wires: Vec<Wire> = (0..SIG_WORDS).map(|_| b.add_witness()).collect();
        let cp = recompute_ctilde(&b, &fc, &nc, &hc, &key_wires, &msg_wires, &sig_wires);
        let want: Vec<Wire> = (0..6).map(|_| b.add_inout()).collect();
        for i in 0..6 {
            b.assert_eq("c", cp[i], want[i]);
        }
        let circuit = b.build();
        let s = CircuitStat::collect(&circuit);
        eprintln!(
            "FULL: n_gates={} n_eval_insn={} n_and={} n_mul={} value_vec_len={}",
            s.n_gates, s.n_eval_insn, s.n_and_constraints, s.n_mul_constraints, s.value_vec_len
        );
    }

    /// Measurement-only: a single ExpandA polynomial's gate cost.
    #[test]
    #[ignore]
    fn measure_one_expand_a() {
        use binius_frontend::stat::CircuitStat;
        let b = CircuitBuilder::new();
        let rho: Vec<Wire> = (0..4).map(|_| b.add_inout()).collect();
        let _poly = rej_ntt_poly(&b, &rho, 0, 0);
        let circuit = b.build();
        let s = CircuitStat::collect(&circuit);
        eprintln!(
            "ONE ExpandA: n_gates={} n_eval_insn={} n_and={} n_mul={}",
            s.n_gates, s.n_eval_insn, s.n_and_constraints, s.n_mul_constraints
        );
    }

    /// A wrong expected c̃ must make the witness unsatisfiable — the coupling bites.
    #[test]
    fn rejects_wrong_ctilde() {
        let mut rng = StdRng::seed_from_u64(7);
        let policy = Policy { n: 1, m: 1 };
        let mut msg = [0u8; 64];
        rng.fill_bytes(&mut msg);
        let signed = sign(&policy, &msg, &mut rng);
        let vk = signed.keys[0].encode().to_vec();
        let sig = signed.sigs[0].encode().to_vec();
        let mut ctilde = sig[0..48].to_vec();
        assert!(check(&vk, &msg, &sig, &ctilde));
        ctilde[0] ^= 1;
        assert!(!check(&vk, &msg, &sig, &ctilde));
    }
}

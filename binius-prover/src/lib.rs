//! Binius64 prover for the N-of-M ML-DSA-65 statement.
//!
//! The crate proves the *same* statement as `sp1-prover` and
//! `default_verifier::verify_all` — "at least `n` of the supplied ML-DSA-65
//! signatures verify against their slot's verifying key over the message" — but
//! as a hand-written Binius64 circuit rather than a zkVM. See SPEC.md.
//!
//! This module pins the public contract the `tests/xcheck.rs` oracle depends on
//! (SPEC.md §1): [`Case`], [`build`], [`circuit_accepts`], [`prove_and_verify`].
//! The signatures here are frozen; the circuit internals behind them are free to
//! change as the milestones land (SPEC.md §7).
//!
//! ## Milestone status
//! M0 (this scaffold) establishes the `Case` ↔ bytes plumbing, the public API,
//! and the CLI. The in-circuit ML-DSA verification (mod-q gadgets → NTT → SHAKE →
//! decode → single-sig verify → N-of-M) is built from M1 onwards. Until the
//! verify relation exists, [`circuit_accepts`] honestly reports that it cannot
//! accept, so the oracle is RED by design — see the `TODO(stub)` markers.

use std::fmt;

use ml_dsa::{KeyInit, MlDsa65, Seed, Signature, Signer, SigningKey, VerifyingKey};
use policy::Policy;
use rand::RngCore;
use signing::Signed;

/// The serialised, tamperable artifact the oracle feeds the circuit: the policy
/// `(n, m)`, the message, the `m` verifying keys and the `n` signatures — all as
/// their on-the-wire ML-DSA byte encodings, exactly as `sp1-prover` packs them.
///
/// Corruptions mutate these bytes; [`parse`](Case::parse) decodes them back so
/// the reference and the circuit consume byte-identical inputs. A signature whose
/// bytes no longer decode (e.g. a bit flip that breaks the hint encoding or the
/// `‖z‖∞` bound `Signature::decode` enforces) is simply dropped during parsing —
/// faithfully modelling "this signature is invalid", which drives the validity
/// count below `n` and makes the reference reject, exactly as the in-guest
/// `Signature::try_from(..).is_err() => false` path does.
#[derive(Clone, Debug)]
pub struct Case {
    n: usize,
    m: usize,
    msg: Vec<u8>,
    /// `m` verifying-key encodings (1952 B each for ML-DSA-65).
    key_bytes: Vec<Vec<u8>>,
    /// Up to `n` signature encodings (3309 B each).
    sig_bytes: Vec<Vec<u8>>,
}

impl Case {
    /// Pack a freshly-signed bundle into its on-the-wire byte form.
    pub fn from_signed(policy: Policy, msg: &[u8], signed: Signed) -> Case {
        Case {
            n: policy.n,
            m: policy.m,
            msg: msg.to_vec(),
            key_bytes: signed.keys.iter().map(|k| k.encode().to_vec()).collect(),
            sig_bytes: signed.sigs.iter().map(|s| s.encode().to_vec()).collect(),
        }
    }

    /// Decode the stored bytes back into reference types. Keys decode infallibly
    /// (length-checked); signatures that fail to decode are dropped (see the type
    /// docs). The returned tuple is exactly what
    /// `default_verifier::verify_all(&policy, &sigs, &keys, &msg)` consumes.
    pub fn parse(
        &self,
    ) -> (
        Policy,
        Vec<u8>,
        Vec<VerifyingKey<MlDsa65>>,
        Vec<Signature<MlDsa65>>,
    ) {
        let keys = self
            .key_bytes
            .iter()
            .map(|b| {
                VerifyingKey::<MlDsa65>::new_from_slice(b)
                    .expect("verifying-key encoding has fixed length")
            })
            .collect();
        let sigs = self
            .sig_bytes
            .iter()
            .filter_map(|b| Signature::<MlDsa65>::try_from(b.as_slice()).ok())
            .collect();
        (
            Policy { n: self.n, m: self.m },
            self.msg.clone(),
            keys,
            sigs,
        )
    }

    /// The policy this case was built for.
    pub fn policy(&self) -> Policy {
        Policy { n: self.n, m: self.m }
    }

    // ── Corruption strategies (used by the oracle; each yields a case the
    //    reference is expected to REJECT) ─────────────────────────────────────

    /// Flip one random bit somewhere in a random signature's bytes.
    pub fn flip_random_bit_in_signature(&self, rng: &mut impl RngCore) -> Case {
        let mut c = self.clone();
        if !c.sig_bytes.is_empty() {
            let i = (rng.next_u64() as usize) % c.sig_bytes.len();
            flip_bit(&mut c.sig_bytes[i], rng);
        }
        c
    }

    /// Flip one random bit somewhere in a random verifying key's bytes.
    pub fn flip_random_bit_in_pubkey(&self, rng: &mut impl RngCore) -> Case {
        let mut c = self.clone();
        if !c.key_bytes.is_empty() {
            let i = (rng.next_u64() as usize) % c.key_bytes.len();
            flip_bit(&mut c.key_bytes[i], rng);
        }
        c
    }

    /// Flip one random bit somewhere in the message.
    pub fn flip_random_bit_in_message(&self, rng: &mut impl RngCore) -> Case {
        let mut c = self.clone();
        flip_bit(&mut c.msg, rng);
        c
    }

    /// Swap two signatures between slots, so each lands under the wrong key.
    /// (No-op when there are fewer than two signatures — the reference then still
    /// accepts, which the oracle handles as a non-negative.)
    pub fn swap_two_signatures(&self, rng: &mut impl RngCore) -> Case {
        let mut c = self.clone();
        let n = c.sig_bytes.len();
        if n >= 2 {
            let i = (rng.next_u64() as usize) % n;
            let mut j = (rng.next_u64() as usize) % n;
            if i == j {
                j = (j + 1) % n;
            }
            c.sig_bytes.swap(i, j);
        }
        c
    }

    /// Drop the last signer, leaving fewer than `n` signatures: the N-of-M
    /// threshold can no longer be met, so the reference rejects.
    pub fn drop_one_signer(&self) -> Case {
        let mut c = self.clone();
        c.sig_bytes.pop();
        c
    }

    /// Replace slot 0 with a perfectly valid signature for a *different* message
    /// under a fresh key: it decodes fine but does not verify against
    /// `(msg, key[0])`, so the reference rejects.
    pub fn replace_sig_with_other_message(&self, rng: &mut impl RngCore) -> Case {
        let mut c = self.clone();
        if !c.sig_bytes.is_empty() {
            let mut seed = Seed::default();
            rng.fill_bytes(&mut seed[..]);
            let sk = SigningKey::<MlDsa65>::from_seed(&seed);
            let mut other = [0u8; 64];
            rng.fill_bytes(&mut other);
            c.sig_bytes[0] = sk.sign(&other).encode().to_vec();
        }
        c
    }
}

/// Flip a uniformly-random bit of `bytes` in place.
fn flip_bit(bytes: &mut [u8], rng: &mut impl RngCore) {
    if bytes.is_empty() {
        return;
    }
    let bit = (rng.next_u64() as usize) % (bytes.len() * 8);
    bytes[bit / 8] ^= 1 << (bit % 8);
}

/// A circuit built for a fixed policy, reusable across many witnesses.
///
/// At M0 this only carries the policy; from M2 onwards it will own the compiled
/// `binius_frontend::Circuit` and the wire handles needed to bind a `Case` to the
/// witness.
pub struct Circuit {
    policy: Policy,
}

impl Circuit {
    /// The policy this circuit was built for.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// Build the circuit once for a given policy and return a reusable handle.
pub fn build(policy: &Policy) -> Circuit {
    Circuit {
        policy: policy.clone(),
    }
}

/// Errors surfaced by [`circuit_accepts`] / [`prove_and_verify`].
#[derive(Debug)]
pub enum CircuitError {
    /// The in-circuit verification logic is not yet implemented (pre-M4). This is
    /// a milestone placeholder, never a "reject" decision about an input.
    Unimplemented(&'static str),
    /// The witness did not satisfy the circuit's constraints — i.e. the circuit
    /// *rejected* this input. Carries the failing assertion messages.
    Unsatisfied(String),
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitError::Unimplemented(what) => write!(f, "not yet implemented: {what}"),
            CircuitError::Unsatisfied(msg) => write!(f, "constraints unsatisfied: {msg}"),
        }
    }
}

impl std::error::Error for CircuitError {}

/// Populate the witness from a concrete case and check constraint satisfaction
/// only (no proof). Returns `Ok(())` iff the wires satisfy the circuit, and
/// MUST return `Err` for any input the reference rejects.
pub fn circuit_accepts(_circuit: &Circuit, _case: &Case) -> Result<(), CircuitError> {
    // TODO(stub): M1–M5 build the real in-circuit ML-DSA verification (mod-q
    // gadgets → R_q NTT → SHAKE/keccak + decode → single-sig verify → N-of-M).
    // Until the verify relation exists there is no honest acceptance to report,
    // so this returns `Unimplemented`. The oracle is consequently RED on
    // COMPLETENESS only — corrupted cases are still (vacuously) rejected, which
    // keeps SOUNDNESS/DIFFERENTIAL green. Do NOT route this through the reference.
    Err(CircuitError::Unimplemented(
        "in-circuit ML-DSA verification (M1–M5)",
    ))
}

/// Proof-generation metrics, mirrored against the `sp1-prover` RESULTS.md columns.
#[derive(Debug, Clone)]
pub struct ProofStats {
    pub n_bitand: usize,
    pub n_intmul: usize,
    pub n_witness_words: usize,
    pub prove_ms: u128,
    pub proof_bytes: usize,
}

/// Full pipeline: build witness, prove, verify; return proof metrics. Only ever
/// called by the oracle on honest cases that [`circuit_accepts`] already passed.
pub fn prove_and_verify(_circuit: &Circuit, _case: &Case) -> Result<ProofStats, CircuitError> {
    // TODO(stub): M6 wires up the aliased `binius-prover`/`binius-verifier`
    // crates (see Cargo.toml). Unreachable until circuit_accepts succeeds (M4+).
    Err(CircuitError::Unimplemented("proof generation (M6)"))
}

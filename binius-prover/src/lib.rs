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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Mod-q field arithmetic gadgets (SPEC.md §2), the foundation every later layer
/// (NTT, decode, verify) builds on. Internal for now; the public contract below is
/// unchanged.
mod field;

/// In-circuit NTT over `R_q` (SPEC.md §2), built on the [`field`] gadgets. The
/// polynomial-multiplication layer the verify relation (M4) uses for `Â·ẑ`, `ĉ·t̂`.
mod ntt;

/// SHAKE128/SHAKE256 XOFs (SPEC.md §3) built on the upstream Keccak-f[1600]
/// permutation — the hashing layer ExpandA, SampleInBall, μ/tr and c̃′ all use.
mod shake;

/// Byte ↔ coefficient decode/encode (SPEC.md §2): `t1`/`z` unpack into coefficient
/// wires and `w1` re-encode, bridging the packed `inout` bytes to the field layer.
mod decode;

/// `Decompose` + `UseHint` (SPEC.md §4 step 7) on the [`field`] gadgets — turning
/// the recomputed `wp` coefficients into the `w1` high-bits string for `c̃′`.
mod usehint;

/// Rejection sampling for `Â = ExpandA(ρ)` (SPEC.md §3a) — fixed 840-byte SHAKE128
/// squeeze plus a soundly-constrained witnessed compaction of the accepted
/// candidates into the 256 NTT-domain coefficients.
mod sampling;

/// The §4 single-signature `raw_verify_mu` relation (M4): composes every gadget
/// above into the recomputed `c̃′`, which the N-of-M layer (M5) couples to the
/// decoded `c̃` per signature.
mod verify;

use binius_core::constraint_system::ValuesData;
use binius_core::word::Word;
use binius_frontend::CircuitStat;
use binius_utils::serialization::SerializeBytes;
use ml_dsa::{KeyInit, MlDsa65, Seed, Signature, Signer, SigningKey, VerifyingKey};
use policy::Policy;
use rand::RngCore;
use signing::Signed;

use verify::{build_single_sig, SingleSig, MSG_WORDS, SIG_WORDS, VK_WORDS};

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
/// It owns ONE compiled single-signature verify circuit ([`SingleSig`], SPEC.md §4)
/// and the policy. The N-of-M decision (SPEC.md §5) is the host-side aggregation in
/// [`circuit_accepts`]: populate the same circuit once per signature slot and accept
/// iff at least `n` of them satisfy — mirroring
/// `default_verifier::verify_all`'s "count of verifying pairs `≥ n`". Reusing a
/// single sub-circuit keeps peak build memory at ~3 GB regardless of `n` (NOTES).
pub struct Circuit {
    policy: Policy,
    single: SingleSig,
    /// The single-sig constraint system serialized to a temp file, written lazily on
    /// the first [`prove_and_verify`] and reused (it is identical across slots/cases).
    /// `None` until the first proof; the file lives for the process lifetime.
    cs_path: OnceLock<PathBuf>,
}

/// Log of the inverse code rate for the proof system; `1` is the fastest setting and
/// the example default. Shared with the runner via the command line.
const LOG_INV_RATE: usize = 1;

impl Circuit {
    /// The policy this circuit was built for.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Serialize the single-sig constraint system to a temp file (once) and return its
    /// path. The runner deserialises it to set up the prover/verifier.
    fn cs_path(&self) -> Result<&Path, CircuitError> {
        if let Some(p) = self.cs_path.get() {
            return Ok(p);
        }
        let cs = self.single.circuit.constraint_system();
        let mut buf = Vec::new();
        cs.serialize(&mut buf)
            .map_err(|e| CircuitError::Proof(format!("serialize cs: {e}")))?;
        let path = unique_temp_path("mldsa-cs", "bin");
        std::fs::write(&path, &buf)
            .map_err(|e| CircuitError::Proof(format!("write cs {}: {e}", path.display())))?;
        let _ = self.cs_path.set(path);
        Ok(self.cs_path.get().expect("just set"))
    }
}

/// Build the circuit once for a given policy and return a reusable handle.
pub fn build(policy: &Policy) -> Circuit {
    Circuit {
        policy: policy.clone(),
        single: build_single_sig(),
        cs_path: OnceLock::new(),
    }
}

/// Pack a byte slice 8-per-word little-endian, zero-padding the final partial word
/// — the `inout`/`witness` word convention the gadget layer consumes.
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

/// Populate the single-sig circuit for one `(vk, msg, sig)` slot and report whether
/// the witness satisfies it — i.e. whether this signature verifies against this key
/// over this message. Lengths are validated against the fixed ML-DSA-65 encodings;
/// a wrong-length input cannot verify, so it is reported as a non-satisfying slot
/// rather than panicking. This is purely an in-circuit constraint check — the
/// reference verifier is never consulted.
fn slot_verifies(single: &SingleSig, vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let key_words = pack_le(vk);
    let msg_words = pack_le(msg);
    let sig_words = pack_le(sig);
    if key_words.len() != VK_WORDS || msg_words.len() != MSG_WORDS || sig_words.len() != SIG_WORDS {
        return false;
    }

    let mut w = single.circuit.new_witness_filler();
    for (wire, val) in single.key_wires.iter().zip(key_words) {
        w[*wire] = Word::from_u64(val);
    }
    for (wire, val) in single.msg_wires.iter().zip(msg_words) {
        w[*wire] = Word::from_u64(val);
    }
    for (wire, val) in single.sig_wires.iter().zip(sig_words) {
        w[*wire] = Word::from_u64(val);
    }
    single.circuit.populate_wire_witness(&mut w).is_ok()
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
    /// The proof system (setup, prove, or verify) reported an internal error. This
    /// is a machinery fault, never a "reject" decision about an input.
    Proof(String),
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitError::Unimplemented(what) => write!(f, "not yet implemented: {what}"),
            CircuitError::Unsatisfied(msg) => write!(f, "constraints unsatisfied: {msg}"),
            CircuitError::Proof(msg) => write!(f, "proof system error: {msg}"),
        }
    }
}

impl std::error::Error for CircuitError {}

/// Populate the witness from a concrete case and check constraint satisfaction
/// only (no proof). Returns `Ok(())` iff the wires satisfy the circuit, and
/// MUST return `Err` for any input the reference rejects.
pub fn circuit_accepts(circuit: &Circuit, case: &Case) -> Result<(), CircuitError> {
    // N-of-M (SPEC.md §5): mirror `default_verifier::verify_all` — pair each supplied
    // signature with its slot's key, count how many verify, accept iff at least `n`
    // do. Each pair is decided ENTIRELY in-circuit by `slot_verifies` (decode validity
    // + c̃′ == c̃); the reference is never consulted.
    //
    // The corpus only ever supplies `s ≤ n` signatures (honest signs exactly `n`;
    // corruptions drop or mangle, never add). Reaching `n` therefore demands every
    // slot verify, so the host-side count over the original slots coincides exactly
    // with the reference's count over its compacted (decode-dropped) pairing — a
    // dropped or wrong-key signature pushes the count below `n` either way.
    let n = circuit.policy.n;
    let pairs = case.sig_bytes.len().min(case.key_bytes.len());

    let mut valid = 0usize;
    for i in 0..pairs {
        if slot_verifies(
            &circuit.single,
            &case.key_bytes[i],
            &case.msg,
            &case.sig_bytes[i],
        ) {
            valid += 1;
            if valid >= n {
                return Ok(());
            }
        } else if valid + (pairs - 1 - i) < n {
            // Even if every remaining slot verified, the threshold is unreachable.
            break;
        }
    }

    if valid >= n {
        Ok(())
    } else {
        Err(CircuitError::Unsatisfied(format!(
            "only {valid} of the supplied signatures verify in-circuit; threshold n = {n} not met"
        )))
    }
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

/// A process-unique temp path `<tmpdir>/<prefix>-<pid>-<counter>.<ext>`.
fn unique_temp_path(prefix: &str, ext: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("{prefix}-{pid}-{n}.{ext}"))
}

/// Serialize the public / non-public halves of the satisfying witness for one slot to
/// two temp files, returning their paths. The runner reconstructs the `ValueVec` from
/// these plus the constraint system's layout (exactly the `save`/`load-prove` split of
/// the upstream example CLI).
fn write_slot_witness(
    single: &SingleSig,
    vk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(PathBuf, PathBuf), CircuitError> {
    let key_words = pack_le(vk);
    let msg_words = pack_le(msg);
    let sig_words = pack_le(sig);
    if key_words.len() != VK_WORDS || msg_words.len() != MSG_WORDS || sig_words.len() != SIG_WORDS {
        return Err(CircuitError::Unsatisfied("input wrong length".into()));
    }
    let mut w = single.circuit.new_witness_filler();
    for (wire, val) in single.key_wires.iter().zip(key_words) {
        w[*wire] = Word::from_u64(val);
    }
    for (wire, val) in single.msg_wires.iter().zip(msg_words) {
        w[*wire] = Word::from_u64(val);
    }
    for (wire, val) in single.sig_wires.iter().zip(sig_words) {
        w[*wire] = Word::from_u64(val);
    }
    single
        .circuit
        .populate_wire_witness(&mut w)
        .map_err(|e| CircuitError::Unsatisfied(format!("{e:?}")))?;
    let witness = w.into_value_vec();

    let write = |words: &[Word], tag: &str| -> Result<PathBuf, CircuitError> {
        let mut buf = Vec::new();
        ValuesData::borrowed(words)
            .serialize(&mut buf)
            .map_err(|e| CircuitError::Proof(format!("serialize {tag} witness: {e}")))?;
        let path = unique_temp_path(&format!("mldsa-{tag}"), "bin");
        std::fs::write(&path, &buf)
            .map_err(|e| CircuitError::Proof(format!("write {tag} {}: {e}", path.display())))?;
        Ok(path)
    };
    let pub_path = write(witness.public(), "pub")?;
    let nonpub_path = write(witness.non_public(), "nonpub")?;
    Ok((pub_path, nonpub_path))
}

/// Locate (building once if necessary) the `binius-proof-runner` binary. The runner is
/// a workspace-EXCLUDED crate — it owns the upstream `binius-prover`/`binius-verifier`,
/// which must stay out of this crate's dependency closure (see [`Cargo.toml`]). It is
/// built into its own target dir so the nested `cargo build` never contends with the
/// outer `cargo test`'s build lock.
fn runner_binary() -> Result<PathBuf, CircuitError> {
    static RUNNER: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    RUNNER
        .get_or_init(|| build_runner().map_err(|e| e.to_string()))
        .clone()
        .map_err(CircuitError::Proof)
}

fn build_runner() -> Result<PathBuf, CircuitError> {
    // `CARGO_MANIFEST_DIR` is `<repo>/binius-prover`; the runner sits beside it.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest_dir
        .parent()
        .ok_or_else(|| CircuitError::Proof("no parent of manifest dir".into()))?;
    let runner_dir = repo.join("binius-proof-runner");
    let target_dir = runner_dir.join("target");
    let manifest = runner_dir.join("Cargo.toml");
    let bin = target_dir.join("release").join("binius-proof-runner");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .env("RUSTFLAGS", "-C target-cpu=native")
        .status()
        .map_err(|e| CircuitError::Proof(format!("spawn cargo build for runner: {e}")))?;
    if !status.success() {
        return Err(CircuitError::Proof(format!(
            "building binius-proof-runner failed ({status})"
        )));
    }
    if !bin.exists() {
        return Err(CircuitError::Proof(format!(
            "runner binary missing after build: {}",
            bin.display()
        )));
    }
    Ok(bin)
}

/// Full pipeline: build the honest witness, generate a real Binius64 proof and verify
/// it; return proof metrics. Only ever called by the oracle on honest cases that
/// [`circuit_accepts`] already passed.
///
/// The N-of-M statement is the AND of `n` single-signature checks (NOTES; SPEC.md §5),
/// so an honest case is proved by proving each of its `n` slots against the shared
/// single-sig circuit and verifying every proof. Proving runs in the
/// `binius-proof-runner` subprocess (which owns the upstream prover); one invocation
/// per call sets up once and proves all `n` slots. The reported [`ProofStats`] aggregate
/// the `n` proofs: `prove_ms` and `proof_bytes` sum over the slots (the whole N-of-M
/// proof bundle), while the constraint counts are the single-sig circuit's (identical
/// per slot).
pub fn prove_and_verify(circuit: &Circuit, case: &Case) -> Result<ProofStats, CircuitError> {
    let n = circuit.policy.n;
    let single = &circuit.single;
    let pairs = case.sig_bytes.len().min(case.key_bytes.len());
    if pairs < n {
        return Err(CircuitError::Unsatisfied(format!(
            "only {pairs} slots supplied; threshold n = {n} not met"
        )));
    }

    let stat = CircuitStat::collect(&single.circuit);
    let cs_path = circuit.cs_path()?;
    let runner = runner_binary()?;

    // Serialize one witness per slot; collect the temp paths to feed the runner and to
    // clean up afterwards.
    let mut witness_paths: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(n);
    for i in 0..n {
        witness_paths.push(write_slot_witness(
            single,
            &case.key_bytes[i],
            &case.msg,
            &case.sig_bytes[i],
        )?);
    }

    let mut cmd = Command::new(&runner);
    cmd.arg(cs_path).arg(LOG_INV_RATE.to_string());
    for (p, np) in &witness_paths {
        cmd.arg(p).arg(np);
    }
    let output = cmd
        .output()
        .map_err(|e| CircuitError::Proof(format!("spawn runner: {e}")));

    // Best-effort cleanup of the per-slot witness temp files.
    for (p, np) in &witness_paths {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(np);
    }

    let output = output?;
    if !output.status.success() {
        return Err(CircuitError::Proof(format!(
            "runner failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // The runner prints `OK <total_proof_bytes> <total_prove_ms>` on success.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("OK "))
        .ok_or_else(|| {
            CircuitError::Proof(format!("runner gave no OK line; stdout: {}", stdout.trim()))
        })?;
    let mut it = line.split_whitespace().skip(1);
    let parse = |s: Option<&str>, what: &str| -> Result<u128, CircuitError> {
        s.and_then(|v| v.parse::<u128>().ok())
            .ok_or_else(|| CircuitError::Proof(format!("runner OK line missing {what}: {line}")))
    };
    let proof_bytes = parse(it.next(), "proof_bytes")? as usize;
    let prove_ms = parse(it.next(), "prove_ms")?;

    Ok(ProofStats {
        n_bitand: stat.n_and_constraints,
        n_intmul: stat.n_mul_constraints,
        n_witness_words: stat.n_witness,
        prove_ms,
        proof_bytes,
    })
}

#[cfg(test)]
mod m6_tests {
    use super::*;
    use policy::Policy;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// End-to-end smoke test of the M6 subprocess proving path on the cheapest policy:
    /// build → honest sign → `circuit_accepts` → `prove_and_verify` round-trips a real
    /// Binius64 proof. Fast enough to validate the plumbing without the full oracle.
    #[test]
    fn prove_and_verify_round_trip_1of1() {
        let policy = Policy { n: 1, m: 1 };
        let circuit = build(&policy);
        let mut rng = StdRng::seed_from_u64(0xA5A5);
        let mut msg = [0u8; 64];
        rng.fill_bytes(&mut msg);
        let signed = signing::sign(&policy, &msg, &mut rng);
        let case = Case::from_signed(policy, &msg, signed);

        circuit_accepts(&circuit, &case).expect("honest case must satisfy the circuit");
        let stats = prove_and_verify(&circuit, &case).expect("proof must generate and verify");
        assert!(stats.proof_bytes > 0, "proof should be non-empty");
        eprintln!(
            "1-of-1 proof: {} bytes, prove_ms={}, n_bitand={}, n_intmul={}, n_witness={}",
            stats.proof_bytes,
            stats.prove_ms,
            stats.n_bitand,
            stats.n_intmul,
            stats.n_witness_words,
        );
    }
}

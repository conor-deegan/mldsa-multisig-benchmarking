//! xcheck — the success oracle for the Binius64 ML-DSA prover.
//!
//! This file is the ground truth the loop is graded against. It is NOT the
//! circuit. It decides, by an independent and adversarial method, whether the
//! circuit the agent has built actually proves the intended statement.
//!
//! THREE GUARANTEES IT ENFORCES (in priority order):
//!   1. SOUNDNESS  — the circuit must REJECT corrupted inputs. An
//!      under-constrained circuit that accepts everything fails here. This is
//!      the most important property; it cannot be skipped or weakened.
//!   2. DIFFERENTIAL — the in-circuit accept/reject decision must equal the
//!      RustCrypto reference decision (`default_verifier::verify_all`) on every
//!      vector, valid or invalid.
//!   3. COMPLETENESS — for honest N-of-M signature sets, the circuit accepts
//!      AND a real Binius64 proof generates and verifies.
//!
//! HARD RULES (the agent may not edit any of these out — the loop's CLAUDE.md
//! repeats them, and the adversary subagent checks the diff for violations):
//!   - The reference crate `ml-dsa` is read-only ground truth. Do not modify it
//!     and do not route the circuit's decision through it at runtime.
//!   - Corruptions are generated, not enumerated. Do not special-case, skip, or
//!     allowlist any vector to make this pass.
//!   - The witness for the circuit is the n signatures; (policy, message,
//!     verifying keys) are public inout, matching the sp1-prover statement.
//!   - `expect_accept`/`expect_reject` assertions below are fixed. Changing them
//!     to make the suite green is a soundness failure, not a fix.

use policy::Policy;

// ── Contract the loop must implement in the `binius-prover` crate ────────────
// The loop defines exactly this surface (see SPEC.md §API). xcheck depends only
// on it, so the circuit internals stay free to change.
//
//   /// Build the circuit once for a given policy and return a reusable handle.
//   pub fn build(policy: &Policy) -> Circuit;
//
//   /// Populate witness from a concrete case and check constraint satisfaction
//   /// ONLY (no proof). Returns Ok(()) iff the wires satisfy the circuit.
//   /// MUST return Err for any input the reference rejects.
//   pub fn circuit_accepts(c: &Circuit, case: &Case) -> Result<(), CircuitError>;
//
//   /// Full pipeline: build witness, prove, verify. Returns proof metrics.
//   /// Only ever called on honest cases.
//   pub fn prove_and_verify(c: &Circuit, case: &Case) -> Result<ProofStats, CircuitError>;
//
// `Case` is the serialized, tamperable artifact: policy + message + the m
// verifying keys + the n signatures, all as bytes, exactly as on the wire.
use binius_prover::{build, circuit_accepts, prove_and_verify, Case};

use rand::{rngs::StdRng, RngCore, SeedableRng};

const POLICIES: &[(usize, usize)] = &[(1, 1), (2, 3), (6, 10), (3, 5)];
const HONEST_CASES_PER_POLICY: usize = 16;
const CORRUPT_CASES_PER_POLICY: usize = 64;
const SEED: u64 = 0x6D6C_6473_61FE_5EED; // fixed seed → reproducible corpus

/// Reference decision: the existing N-of-M check over the real RustCrypto verify.
/// This is the only thing entitled to be called "correct".
fn reference_accepts(case: &Case) -> bool {
    // signing/default-verifier already give us this; reconstruct from bytes so the
    // circuit and the reference consume byte-identical inputs.
    let (policy, msg, keys, sigs) = case.parse();
    default_verifier::verify_all(&policy, &sigs, &keys, &msg)
}

/// Generate an honest case: real keygen/sign via the `signing` crate.
fn honest_case(policy: Policy, rng: &mut StdRng) -> Case {
    let mut msg = [0u8; 64];
    rng.fill_bytes(&mut msg);
    // `signing::sign` does real ML-DSA-65 keygen + signs with the first n keys.
    let signed = signing::sign(&policy, &msg, rng);
    Case::from_signed(policy, &msg, signed)
}

/// Corruption strategies. GENERIC, not an allowlist of known-bad vectors.
/// Each returns a case the reference is expected to REJECT.
fn corrupt(base: &Case, rng: &mut StdRng) -> Case {
    match rng.next_u32() % 6 {
        0 => base.flip_random_bit_in_signature(rng), // mangle a z/h/c byte
        1 => base.flip_random_bit_in_pubkey(rng),     // mangle a t1/rho byte
        2 => base.flip_random_bit_in_message(rng),
        3 => base.swap_two_signatures(rng),           // sig under wrong key slot
        4 => base.drop_one_signer(),                  // n-1 valid → must fail N-of-M
        5 => base.replace_sig_with_other_message(rng),// valid sig, wrong message
        _ => unreachable!(),
    }
}

#[test]
fn xcheck() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut failures: Vec<String> = Vec::new();

    for &(n, m) in POLICIES {
        let policy = Policy { n, m };
        let circuit = build(&policy);

        // 1+3. Honest cases: reference accepts, circuit accepts, proof round-trips.
        for i in 0..HONEST_CASES_PER_POLICY {
            let case = honest_case(policy.clone(), &mut rng);
            assert!(
                reference_accepts(&case),
                "reference rejected an honest {n}-of-{m} case #{i}; signing/Case is wrong"
            );
            if let Err(e) = circuit_accepts(&circuit, &case) {
                failures.push(format!("COMPLETENESS {n}-of-{m} #{i}: circuit rejected honest case: {e}"));
                continue;
            }
            // Only round-trip a couple per policy; proving is slow.
            if i < 2 {
                if let Err(e) = prove_and_verify(&circuit, &case) {
                    failures.push(format!("PROOF {n}-of-{m} #{i}: prove/verify failed: {e}"));
                }
            }
        }

        // 1+2. Corrupted cases: reference rejects, so circuit MUST reject, and the
        // two decisions must agree.
        for i in 0..CORRUPT_CASES_PER_POLICY {
            let base = honest_case(policy.clone(), &mut rng);
            let bad = corrupt(&base, &mut rng);

            let ref_dec = reference_accepts(&bad);
            let cir_dec = circuit_accepts(&circuit, &bad).is_ok();

            if cir_dec != ref_dec {
                failures.push(format!(
                    "DIFFERENTIAL {n}-of-{m} #{i}: circuit={cir_dec} reference={ref_dec} \
                     (corruption disagreement — likely under-constrained circuit)"
                ));
            }
            // Belt-and-braces: a corruption that the reference still accepts is not a
            // useful negative; skip it. Otherwise the circuit MUST have rejected.
            if !ref_dec && cir_dec {
                failures.push(format!(
                    "SOUNDNESS {n}-of-{m} #{i}: circuit ACCEPTED an input the reference rejected"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "xcheck found {} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

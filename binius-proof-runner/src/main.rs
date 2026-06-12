//! Out-of-process Binius64 prover for the `binius-prover` crate.
//!
//! Invocation:
//!
//! ```text
//! binius-proof-runner <cs.bin> <log_inv_rate> <pub0.bin> <nonpub0.bin> [<pub1.bin> <nonpub1.bin> ...]
//! ```
//!
//! It deserialises the constraint system, sets up the SHA-256 (`StdHashSuite`)
//! prover/verifier ONCE, then for each `(public, non-public)` witness pair reconstructs
//! the `ValueVec`, generates a real proof, and verifies it. On success it prints
//! `OK <total_proof_bytes> <total_prove_ms>` to stdout and exits 0; on any failure it
//! prints the error to stderr and exits 1.
//!
//! Splitting the prover into a separate, workspace-excluded binary keeps the upstream
//! `binius-prover` package out of our crate's dependency closure — otherwise the frozen
//! oracle command `cargo test -p binius-prover` is ambiguous (two packages share that
//! name). See `binius-proof-runner/Cargo.toml`.

use std::{path::Path, process::ExitCode, time::Instant};

use binius_core::constraint_system::{ConstraintSystem, ValueVec, ValuesData};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, Prover};
use binius_utils::serialization::DeserializeBytes;
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    Verifier,
};

type Suite = StdHashSuite;

fn read_deser<T: DeserializeBytes>(path: &str) -> Result<T, String> {
    let buf = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    T::deserialize(buf.as_slice()).map_err(|e| format!("deserialize {path}: {e}"))
}

fn run() -> Result<(usize, u128), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 || (args.len() - 2) % 2 != 0 {
        return Err(format!(
            "usage: <cs> <log_inv_rate> <pub> <nonpub> [<pub> <nonpub> ...]; got {} args",
            args.len()
        ));
    }
    let cs_path = &args[0];
    let log_inv_rate: usize = args[1]
        .parse()
        .map_err(|e| format!("log_inv_rate parse: {e}"))?;

    if !Path::new(cs_path).exists() {
        return Err(format!("cs file missing: {cs_path}"));
    }
    let cs: ConstraintSystem = read_deser(cs_path)?;
    let layout = cs.value_vec_layout.clone();

    // Set up prover + verifier once; reused across all witness pairs.
    let verifier =
        Verifier::<Suite>::setup(cs, log_inv_rate).map_err(|e| format!("verifier setup: {e}"))?;
    let prover = Prover::<OptimalPackedB128, Suite>::setup(verifier.clone())
        .map_err(|e| format!("prover setup: {e}"))?;

    let mut total_bytes = 0usize;
    let mut total_ms = 0u128;
    let pairs = &args[2..];
    for pair in pairs.chunks(2) {
        let pub_data: ValuesData = read_deser(&pair[0])?;
        let non_pub: ValuesData = read_deser(&pair[1])?;
        let witness =
            ValueVec::new_from_data(layout.clone(), pub_data.into_owned(), non_pub.into_owned())
                .map_err(|e| format!("reconstruct witness: {e}"))?;

        let t0 = Instant::now();
        let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
        prover
            .prove(witness.clone(), &mut prover_transcript)
            .map_err(|e| format!("prove: {e}"))?;
        let proof = prover_transcript.finalize();
        total_ms += t0.elapsed().as_millis();
        total_bytes += proof.len();

        let mut verifier_transcript = VerifierTranscript::new(StdChallenger::default(), proof);
        verifier
            .verify(witness.public(), &mut verifier_transcript)
            .map_err(|e| format!("verify: {e}"))?;
        verifier_transcript
            .finalize()
            .map_err(|e| format!("verify-finalize: {e}"))?;
    }

    Ok((total_bytes, total_ms))
}

fn main() -> ExitCode {
    match run() {
        Ok((bytes, ms)) => {
            println!("OK {bytes} {ms}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("binius-proof-runner error: {e}");
            ExitCode::FAILURE
        }
    }
}

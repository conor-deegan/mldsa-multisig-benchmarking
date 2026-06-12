//! CLI surface, mirroring `sp1-prover` so the result columns line up:
//!
//!   cargo run -p binius-prover --release            build + check constraints
//!   cargo run -p binius-prover --release -- --prove  also prove + verify

use binius_prover::{build, circuit_accepts, prove_and_verify, Case};
use policy::Policy;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {
    let prove = std::env::args().any(|a| a == "--prove");

    let policy = Policy::new(6, 10);
    println!(
        "binius-prover — ML-DSA-65 {}-of-{} (Binius64 circuit)",
        policy.n, policy.m
    );

    // A deterministic honest case so repeated CLI runs are reproducible.
    let mut rng = StdRng::seed_from_u64(0xB1A1_2025_0601_2025);
    let mut msg = [0u8; 64];
    rng.fill_bytes(&mut msg);
    let signed = signing::sign(&policy, &msg, &mut rng);
    let case = Case::from_signed(policy.clone(), &msg, signed);

    let circuit = build(&policy);

    match circuit_accepts(&circuit, &case) {
        Ok(()) => println!("constraints satisfied for the honest witness"),
        Err(e) => println!("circuit_accepts: {e}"),
    }

    if prove {
        match prove_and_verify(&circuit, &case) {
            Ok(s) => println!(
                "proof verified: {} bytes, {} ms (n_bitand={}, n_intmul={}, witness_words={})",
                s.proof_bytes, s.prove_ms, s.n_bitand, s.n_intmul, s.n_witness_words
            ),
            Err(e) => println!("prove_and_verify: {e}"),
        }
    }
}

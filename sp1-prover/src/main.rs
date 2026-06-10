use policy::Policy;
use sp1_prover::{build_stdin, GUEST_ELF};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use std::time::Instant;

fn main() {
    sp1_sdk::utils::setup_logger();
    // Default is execute-only (fast: cycle counts + tamper check, no proving).
    // Pass `--prove` to also generate + verify a core proof (slow).
    let do_prove = std::env::args().any(|a| a == "--prove");

    let policy = Policy::new(6, 10);
    let client = ProverClient::from_env();

    // ---- Execute mode: cycle count (portable, host-independent) ----
    let (mut output, report) = client
        .execute(GUEST_ELF, build_stdin(&policy, false))
        .run()
        .unwrap();
    let n: u32 = output.read();
    let _m: u32 = output.read();
    let ok: bool = output.read();
    let cycles = report.total_instruction_count();
    println!("\n==== EXECUTE (no proof) ====");
    println!("policy            : {}-of-{}", policy.n, policy.m);
    println!("all valid (in zkVM): {ok}");
    println!("total cycles      : {cycles}   <- PORTABLE comparison metric");
    println!("cycles / signature: {}   <- PORTABLE", cycles / n as u64);

    // ---- Tamper: flip one signature byte; the in-guest check must fail ----
    let (mut out, _) = client
        .execute(GUEST_ELF, build_stdin(&policy, true))
        .run()
        .unwrap();
    let _n: u32 = out.read();
    let _m: u32 = out.read();
    let tampered_ok: bool = out.read();
    println!("\n==== TAMPER (one signature byte flipped) ====");
    println!("all valid (in zkVM): {tampered_ok}   <- false: proof is bound to real verification");
    assert!(!tampered_ok, "tampered input must not verify");

    // ---- Prove mode: core proof (only with --prove; slow) ----
    if !do_prove {
        println!("\n(execute-only; pass --prove to generate + verify a proof)");
        return;
    }
    let pk = client.setup(GUEST_ELF).expect("setup");

    let t = Instant::now();
    let proof = client
        .prove(&pk, build_stdin(&policy, false))
        .run()
        .expect("prove");
    let prove_time = t.elapsed();

    let t = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify");
    let verify_time = t.elapsed();
    println!("proof verified");

    let proof_size = bincode::serialize(&proof).unwrap().len();
    println!("\n==== PROVE (core proof) ====");
    println!("mode              : core (compression/Groth16 OFF)");
    println!("prove time        : {prove_time:.2?}   <- MacBook-relative, NOT a deployable cost");
    println!("verify time       : {verify_time:.2?}   <- MacBook-relative");
    println!("proof size        : {proof_size} bytes   <- MacBook-relative");
}

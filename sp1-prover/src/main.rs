use policy::Policy;
use sp1_prover::{build_stdin, GUEST_ELF};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use std::time::Instant;

fn main() {
    sp1_sdk::utils::setup_logger();
    // Default is execute-only (fast: cycle counts + tamper check, no proving).
    //   --prove    also generate + verify a core proof (slow)
    //   --profile  print a host-side opcode breakdown of the execute run, then stop
    //              (reads the same report; does NOT change the guest ELF or any numbers)
    let do_prove = std::env::args().any(|a| a == "--prove");
    let do_profile = std::env::args().any(|a| a == "--profile");

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
    println!("precompile syscalls (non-zero):");
    for (code, count) in report.syscall_counts.iter() {
        if *count > 0 {
            println!("  {code:?}: {count}");
        }
    }

    // ---- Profile mode: where do the remaining (non-precompiled) cycles go? ----
    // Pure host-side analysis of the execute report above; returns before tamper/
    // prove so it cannot affect those commands' output.
    if do_profile {
        let mut by_op: Vec<(String, u64)> = report
            .opcode_counts
            .iter()
            .map(|(op, &c)| (format!("{op:?}"), c))
            .filter(|(_, c)| *c > 0)
            .collect();
        by_op.sort_by(|a, b| b.1.cmp(&a.1));

        let total: u64 = by_op.iter().map(|(_, c)| *c).sum();
        let bucket = |names: &[&str]| -> u64 {
            by_op
                .iter()
                .filter(|(o, _)| names.contains(&o.as_str()))
                .map(|(_, c)| *c)
                .sum()
        };
        let mul = bucket(&["MUL", "MULH", "MULHU", "MULHSU", "MULW"]);
        let divrem = bucket(&[
            "DIV", "DIVU", "REM", "REMU", "DIVW", "DIVUW", "REMW", "REMUW",
        ]);
        let load = bucket(&["LB", "LH", "LW", "LBU", "LHU", "LWU", "LD"]);
        let store = bucket(&["SB", "SH", "SW", "SD"]);
        let branch = bucket(&["BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU", "JAL", "JALR"]);
        let other = total - mul - divrem - load - store - branch;
        let pct = |x: u64| 100.0 * x as f64 / total as f64;

        println!("\n==== PROFILE (execute; host-side opcode breakdown) ====");
        println!(
            "RISC-V instructions: {total}  (keccak-f runs as a syscall, counted above, not here)"
        );
        println!("by category:");
        println!("  multiply  (MUL*)       : {mul:>11}  ({:.1}%)", pct(mul));
        println!(
            "  divide/rem (DIV*/REM*) : {divrem:>11}  ({:.1}%)",
            pct(divrem)
        );
        println!("  memory load            : {load:>11}  ({:.1}%)", pct(load));
        println!(
            "  memory store           : {store:>11}  ({:.1}%)",
            pct(store)
        );
        println!(
            "  branch/jump            : {branch:>11}  ({:.1}%)",
            pct(branch)
        );
        println!(
            "  other (ALU/imm/system) : {other:>11}  ({:.1}%)",
            pct(other)
        );
        println!("top 12 opcodes:");
        for (op, c) in by_op.iter().take(12) {
            println!("  {op:<6}: {c:>11}  ({:.1}%)", pct(*c));
        }
        return;
    }

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

    // sp1-cuda's blocking client panics in its Drop impls ("no reactor running")
    // because they spawn a Tokio cleanup task, but the runtime is already gone by
    // the time main returns -> panic-in-destructor -> abort. The proof above is
    // already generated + verified, so flush and exit cleanly to skip those
    // teardown-only destructors. CUDA build only; the CPU/Mac build is unaffected.
    #[cfg(feature = "cuda")]
    {
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        std::process::exit(0);
    }
}

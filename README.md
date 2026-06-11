# mldsa-multisig-benchmarking

Baseline benchmark for verifying N-of-M ML-DSA-65 multi-sig with and without ZK.

View the results [here](./RESULTS.md)

## Crates

- `ml-dsa` — local editable copy of the RustCrypto crate used as the single source of all keygen/sign/verify.
- `policy` — `Policy { n, m }`.
- `signing` — `sign(policy)`: generates `m` keypairs, signs a fixed message with the first `n`, returns the `n` signatures + verifying keys + message.
- `default-verifier` — `verify_all(policy, sigs, keys, msg)`: N-of-M threshold check that passes only if at least `policy.n` signatures are valid (fewer signers or any bad signature fails). Plus a Criterion bench.
- `demo` — runnable binary that prints each step (policy, message, per-signer keys/signatures + sizes, verification results).
- `sp1-prover` — proves the SAME statement in the SP1 zkVM instead of returning a bool: the guest (`sp1-prover/program`) runs the `verify_all` check, and the host produces/verifies a proof. Reports portable RISC-V cycles plus (MacBook-relative) proving time/size.

## Usage

```sh
cargo build --workspace
cargo run   -p demo              # print the full flow, step by step
cargo test  -p default-verifier  # all-valid, tampered, and too-few-signers tests
cargo bench -p default-verifier  # times verifying 6-of-10
```

### SP1 prover

Needs SP1 (`sp1up`) and `protoc`. The host crate is named `sp1-prover`, which collides
with SP1's own `sp1-prover` dependency, so qualify cargo's `-p` with `@0.1.0`:

```sh
cargo run   -p sp1-prover@0.1.0 --release              # execute-only: cycles + tamper (fast)
cargo run   -p sp1-prover@0.1.0 --release -- --profile  # opcode breakdown of the execute run
cargo run   -p sp1-prover@0.1.0 --release -- --prove   # also generate + verify a proof (slow)
cargo bench -p sp1-prover@0.1.0                        # times core-proof generation (slow: ~min/proof)
```

Execute-only is the default so you can check cycle counts without waiting for a proof;
add `--prove` to generate and verify a core proof. `--profile` is host-side analysis of
the same execute run (a sorted opcode histogram bucketed into multiply / divide /
memory / branch); it reads the report only, so it never changes the guest ELF or any of
the tracked cycle/time numbers.

Metrics: **RISC-V cycles** are the portable, host-independent comparison number;
**proving time and proof size are MacBook-relative.**
The guest is built for `riscv64im-succinct-zkvm-elf` by `sp1-prover/build.rs`.

The guest's `Cargo.toml` patches `sha3` to SP1's Keccak-precompile fork
(`patch-sha3-0.11.0-sp1-6.0.0`), routing every SHAKE permutation through the
`KECCAK_PERMUTE` precompile. The patch applies only in the guest workspace, so the
native host build keeps the stock crates.io `sha3`.

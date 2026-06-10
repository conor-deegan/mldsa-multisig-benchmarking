# mldsa-multisig-benchmarking

Baseline benchmark for verifying N-of-M ML-DSA-65 signatures over the same message.

## Crates

- `ml-dsa` — local editable copy of the RustCrypto crate used as the single source of all keygen/sign/verify.
- `policy` — `Policy { n, m }`.
- `signing` — `sign(policy)`: generates `m` keypairs, signs a fixed message with the first `n`, returns the `n` signatures + verifying keys + message.
- `default-verifier` — `verify_all(policy, sigs, keys, msg)`: N-of-M threshold check that passes only if at least `policy.n` signatures are valid (fewer signers or any bad signature fails). Plus a Criterion bench.
- `demo` — runnable binary that prints each step (policy, message, per-signer keys/signatures + sizes, verification results).

## Usage

```sh
cargo build --workspace
cargo run   -p demo              # print the full flow, step by step
cargo test  -p default-verifier  # all-valid, tampered, and too-few-signers tests
cargo bench -p default-verifier  # times verifying 6-of-10
```

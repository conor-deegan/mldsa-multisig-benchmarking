use policy::Policy;
use sp1_sdk::{include_elf, Elf, SP1Stdin};

/// The compiled guest ELF (built by build.rs via sp1_build).
pub const GUEST_ELF: Elf = include_elf!("sp1-prover-program");

/// Run `signing::sign` once and pack the inputs the guest expects: the policy
/// `(n, m)`, the N signatures and N verifying keys as their ML-DSA encoded
/// bytes, and the message. If `tamper`, flip one byte of the first signature so
/// the in-guest verification must fail.
pub fn build_stdin(policy: &Policy, tamper: bool) -> SP1Stdin {
    let (sigs, keys, msg) = signing::sign(policy);
    let mut sig_bytes: Vec<Vec<u8>> = sigs.iter().map(|s| s.encode().to_vec()).collect();
    let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.encode().to_vec()).collect();
    if tamper {
        sig_bytes[0][0] ^= 0xFF;
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&(policy.n as u32));
    stdin.write(&(policy.m as u32));
    stdin.write(&sig_bytes);
    stdin.write(&key_bytes);
    stdin.write(&msg);
    stdin
}

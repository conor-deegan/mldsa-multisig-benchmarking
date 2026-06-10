#![no_main]
sp1_zkvm::entrypoint!(main);

use ml_dsa::{KeyInit, MlDsa65, Signature, Verifier, VerifyingKey};

pub fn main() {
    // Inputs: policy (n, m), N signatures, N verifying keys, and the message,
    // signatures and keys passed as their ML-DSA encoded bytes.
    let n = sp1_zkvm::io::read::<u32>() as usize;
    let m = sp1_zkvm::io::read::<u32>();
    let sigs = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let keys = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let msg = sp1_zkvm::io::read::<Vec<u8>>();

    // Same statement as default-verifier::verify_all: verify each signature
    // against its key over the message, and require at least N to pass.
    let valid = (0..n)
        .filter(|&i| {
            let vk = VerifyingKey::<MlDsa65>::new_from_slice(&keys[i]).unwrap();
            match Signature::<MlDsa65>::try_from(sigs[i].as_slice()) {
                Ok(sig) => vk.verify(&msg, &sig).is_ok(),
                Err(_) => false,
            }
        })
        .count();
    let ok = valid >= n;

    // Public outputs: policy, the verification result, the message, and the key set.
    sp1_zkvm::io::commit(&(n as u32));
    sp1_zkvm::io::commit(&m);
    sp1_zkvm::io::commit(&ok);
    sp1_zkvm::io::commit(&msg);
    sp1_zkvm::io::commit(&keys);
}

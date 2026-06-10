use ml_dsa::{Keypair, MlDsa65, Seed, Signature, Signer, SigningKey, VerifyingKey};
use policy::Policy;

/// Generate `m` keypairs, then sign the fixed message with the first `n` of them.
/// Returns the `n` signatures, the `n` matching verifying keys, and the message.
///
/// Keys are derived from fixed per-index seeds (not the OS RNG), so a given policy
/// always produces the same keys/signatures and the zkVM cycle count is reproducible.
pub fn sign(policy: &Policy) -> (Vec<Signature<MlDsa65>>, Vec<VerifyingKey<MlDsa65>>, Vec<u8>) {
    let msg = b"benchmark message".to_vec();
    let keys: Vec<SigningKey<MlDsa65>> = (0..policy.m)
        .map(|i| {
            let mut seed = Seed::default();
            seed[0] = i as u8;
            SigningKey::from_seed(&seed)
        })
        .collect();
    (
        keys[..policy.n].iter().map(|k| k.sign(&msg)).collect(),
        keys[..policy.n].iter().map(|k| k.verifying_key()).collect(),
        msg,
    )
}

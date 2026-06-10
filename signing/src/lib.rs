use ml_dsa::{Generate, Keypair, MlDsa65, Signature, Signer, SigningKey, VerifyingKey};
use policy::Policy;

/// Generate `m` keypairs, then sign the fixed message with the first `n` of them.
/// Returns the `n` signatures, the `n` matching verifying keys, and the message.
pub fn sign(policy: &Policy) -> (Vec<Signature<MlDsa65>>, Vec<VerifyingKey<MlDsa65>>, Vec<u8>) {
    let msg = b"benchmark message".to_vec();
    let keys: Vec<SigningKey<MlDsa65>> = (0..policy.m).map(|_| SigningKey::generate()).collect();
    (
        keys[..policy.n].iter().map(|k| k.sign(&msg)).collect(),
        keys[..policy.n].iter().map(|k| k.verifying_key()).collect(),
        msg,
    )
}

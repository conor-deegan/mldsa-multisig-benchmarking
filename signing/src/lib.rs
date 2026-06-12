use ml_dsa::{Keypair, MlDsa65, Seed, Signature, Signer, SigningKey, VerifyingKey};
use policy::Policy;
use rand::RngCore;

/// The public artefacts of an N-of-M signing round: the full set of `m`
/// verifying keys, and the `n` signatures produced by the first `n` signers
/// over the message. This is exactly what the verifier (and the circuit) sees —
/// no secret key material crosses this boundary.
pub struct Signed {
    /// All `m` verifying keys, in slot order.
    pub keys: Vec<VerifyingKey<MlDsa65>>,
    /// The `n` signatures, slot `i` signed by `keys[i]`.
    pub sigs: Vec<Signature<MlDsa65>>,
}

/// Generate `m` fresh ML-DSA-65 keypairs (seeded from `rng`) and sign `msg` with
/// the first `n` of them. Returns the public `Signed` bundle. This is the path
/// the xcheck oracle drives, so the keys differ from case to case.
pub fn sign(policy: &Policy, msg: &[u8], rng: &mut impl RngCore) -> Signed {
    let keys: Vec<SigningKey<MlDsa65>> = (0..policy.m)
        .map(|_| {
            let mut seed = Seed::default();
            rng.fill_bytes(&mut seed[..]);
            SigningKey::from_seed(&seed)
        })
        .collect();
    Signed {
        keys: keys.iter().map(|k| k.verifying_key()).collect(),
        sigs: keys[..policy.n].iter().map(|k| k.sign(msg)).collect(),
    }
}

/// Deterministic variant kept for the benchmark / demo crates: derive `m`
/// keypairs from fixed per-index seeds and sign a fixed message with the first
/// `n`. A given policy always yields the same keys/signatures, so cycle counts
/// and timings are reproducible. Returns the `n` signatures, the `n` matching
/// verifying keys, and the message — the historical tuple shape.
pub fn sign_default(
    policy: &Policy,
) -> (Vec<Signature<MlDsa65>>, Vec<VerifyingKey<MlDsa65>>, Vec<u8>) {
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

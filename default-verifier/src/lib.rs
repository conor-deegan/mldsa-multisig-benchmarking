use ml_dsa::{MlDsa65, Signature, Verifier, VerifyingKey};
use policy::Policy;

/// N-of-M threshold check: verify each signature against its matching key over
/// `msg`, and pass only if at least `policy.n` of them are valid. Fewer than `n`
/// valid signatures (too few signers, or a bad signature) fails.
pub fn verify_all(
    policy: &Policy,
    sigs: &[Signature<MlDsa65>],
    keys: &[VerifyingKey<MlDsa65>],
    msg: &[u8],
) -> bool {
    let valid = sigs
        .iter()
        .zip(keys)
        .filter(|(sig, key)| key.verify(msg, sig).is_ok())
        .count();
    valid >= policy.n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_signatures_verify() {
        let policy = Policy::new(6, 10);
        let (sigs, keys, msg) = signing::sign(&policy);
        assert!(verify_all(&policy, &sigs, &keys, &msg));
    }

    #[test]
    fn tampered_signature_fails() {
        let policy = Policy::new(6, 10);
        let (mut sigs, keys, msg) = signing::sign(&policy);
        let mut enc = sigs[0].encode();
        enc[0] ^= 0xFF;
        sigs[0] = Signature::decode(&enc).unwrap();
        assert!(!verify_all(&policy, &sigs, &keys, &msg));
    }

    #[test]
    fn too_few_signatures_fails() {
        let policy = Policy::new(6, 10);
        let (sigs, keys, msg) = signing::sign(&policy);
        assert!(!verify_all(
            &policy,
            &sigs[..policy.n - 1],
            &keys[..policy.n - 1],
            &msg
        ));
    }
}

use policy::Policy;

// First 8 bytes as hex, just enough to eyeball that values differ.
fn head(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let policy = Policy::new(6, 10);
    println!("ML-DSA-65 N-of-M multisig — baseline demo");
    println!("=========================================\n");
    println!(
        "Policy: {}-of-{}  (need {} of {} signers)",
        policy.n, policy.m, policy.n, policy.m
    );

    let (mut sigs, keys, msg) = signing::sign(&policy);
    println!(
        "Message: {:?} ({} bytes)",
        String::from_utf8_lossy(&msg),
        msg.len()
    );
    println!(
        "\nGenerated {} keypairs, signed with the first {}:\n",
        policy.m, policy.n
    );

    for i in 0..policy.n {
        let vk = keys[i].encode();
        let sig = sigs[i].encode();
        let ok = default_verifier::verify_all(&Policy::new(1, 1), &sigs[i..=i], &keys[i..=i], &msg);
        println!("Signer {}:", i + 1);
        println!("  verifying key: {} bytes  {}...", vk.len(), head(&vk));
        println!("  signature:     {} bytes  {}...", sig.len(), head(&sig));
        println!("  verifies:      {}", ok);
    }

    let all = default_verifier::verify_all(&policy, &sigs, &keys, &msg);
    println!(
        "\nThreshold: need {} valid. With all {} supplied: {}",
        policy.n,
        policy.n,
        if all { "PASS ✓" } else { "FAIL ✗" }
    );

    // Too few signed: supply one fewer than the threshold, expect failure.
    let short = default_verifier::verify_all(
        &policy,
        &sigs[..policy.n - 1],
        &keys[..policy.n - 1],
        &msg,
    );
    println!(
        "With only {} supplied (< {}): {}",
        policy.n - 1,
        policy.n,
        if short { "PASS ✗" } else { "FAIL ✓ (expected)" }
    );

    // Tamper: flip one byte of signature 1, dropping valid count below the threshold.
    let mut enc = sigs[0].encode();
    enc[0] ^= 0xFF;
    sigs[0] = ml_dsa::Signature::decode(&enc).unwrap();
    let tampered = default_verifier::verify_all(&policy, &sigs, &keys, &msg);
    println!(
        "With 1 signature tampered: {}",
        if tampered {
            "PASS ✗"
        } else {
            "FAIL ✓ (expected)"
        }
    );
}

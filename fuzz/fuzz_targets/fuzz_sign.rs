#![no_main]
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::Ph;
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};


// Helper to create deterministic RNG from data
fn create_rng(seed_data: &[u8]) -> ChaCha20Rng {
    let seed = if seed_data.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed_data[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..seed_data.len()].copy_from_slice(seed_data);
        arr
    };
    ChaCha20Rng::from_seed(seed)
}


// Helper function to test signing operations for a specific parameter set
fn fuzz_signer_for_params<S, V>(
    data: &[u8], rng: &mut impl CryptoRngCore, keypair: &(V, S), ctx: &[u8],
) where
    S: Signer<PublicKey = V>,
    V: Verifier<Signature = S::Signature> + SerDes + Clone,
    <S as Signer>::Signature: PartialEq,
    <V as SerDes>::ByteArray: PartialEq,
{
    let (pk, sk) = keypair;

    // Test regular signing
    if let Ok(sig1) = sk.try_sign_with_rng(rng, data, ctx) {
        // Verify the signature works
        assert!(pk.clone().verify(data, &sig1, ctx));

        // Test that signing the same message twice produces different signatures
        if let Ok(sig2) = sk.try_sign_with_rng(rng, data, ctx) {
            // Signatures should be different (due to randomization)
            assert!(sig1 != sig2);
            // But both should verify
            assert!(pk.clone().verify(data, &sig2, ctx));
        }

        // Verify public key derivation
        let derived_pk = sk.get_public_key();
        assert!(derived_pk.clone().into_bytes() == pk.clone().into_bytes());
        assert!(derived_pk.verify(data, &sig1, ctx));
    }

    // Test hash signing with different hash functions
    for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
        if let Ok(sig) = sk.try_hash_sign_with_rng(rng, data, ctx, &ph) {
            // Verify the hash signature works
            assert!(pk.hash_verify(data, &sig, ctx, &ph));

            // Test that hash signing the same message twice produces different signatures
            if let Ok(sig2) = sk.try_hash_sign_with_rng(rng, data, ctx, &ph) {
                assert!(sig != sig2);
                assert!(pk.hash_verify(data, &sig2, ctx, &ph));
            }

            // Verify signature doesn't work with wrong hash function
            let wrong_ph = match ph {
                Ph::SHA256 => Ph::SHA512,
                _ => Ph::SHA256,
            };
            assert!(!pk.hash_verify(data, &sig, ctx, &wrong_ph));
        }
    }
}


fuzz_target!(|data: &[u8]| {
    // Skip empty inputs
    if data.is_empty() {
        return;
    }

    // Create deterministic RNG from first part of input
    let mut rng = create_rng(data);

    // Generate keypairs using the RNG
    let ml_dsa_44_keypair = ml_dsa_44::KG::try_keygen_with_rng(&mut rng).unwrap();
    let ml_dsa_65_keypair = ml_dsa_65::KG::try_keygen_with_rng(&mut rng).unwrap();
    let ml_dsa_87_keypair = ml_dsa_87::KG::try_keygen_with_rng(&mut rng).unwrap();

    // Use first byte as context length
    let ctx_len = (data[0] as usize) % 8;
    let (ctx, msg) = data.split_at(ctx_len.min(data.len()));

    // Test all parameter sets
    fuzz_signer_for_params(msg, &mut rng, &ml_dsa_44_keypair, ctx);
    fuzz_signer_for_params(msg, &mut rng, &ml_dsa_65_keypair, ctx);
    fuzz_signer_for_params(msg, &mut rng, &ml_dsa_87_keypair, ctx);

    // Test edge cases
    if let Some((pk, sk)) = Some(&ml_dsa_65_keypair) {
        // Test empty message
        if let Ok(sig) = sk.try_sign_with_rng(&mut rng, &[], ctx) {
            assert!(pk.verify(&[], &sig, ctx));
        }

        // Test empty context
        if let Ok(sig) = sk.try_sign_with_rng(&mut rng, msg, &[]) {
            assert!(pk.verify(msg, &sig, &[]));
        }

        // Test large message (if we have enough data)
        if msg.len() > 100 {
            if let Ok(sig) = sk.try_sign_with_rng(&mut rng, msg, ctx) {
                assert!(pk.verify(msg, &sig, ctx));
            }
        }

        // Test signing with different RNG seeds
        if msg.len() > 32 {
            let mut different_rng = create_rng(&msg[..32]);
            if let Ok(sig1) = sk.try_sign_with_rng(&mut rng, msg, ctx) {
                if let Ok(sig2) = sk.try_sign_with_rng(&mut different_rng, msg, ctx) {
                    assert!(sig1 != sig2);
                    assert!(pk.verify(msg, &sig1, ctx));
                    assert!(pk.verify(msg, &sig2, ctx));
                }
            }
        }
    }
});

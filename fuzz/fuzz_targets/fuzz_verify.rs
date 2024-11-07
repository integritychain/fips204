#![no_main]
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::Ph;
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use libfuzzer_sys::fuzz_target;


// Helper function to test a specific parameter set
fn fuzz_verify_for_params<S, V>(data: &[u8], keypair: &(V, S), ctx: &[u8])
where
    S: Signer,
    V: Verifier<Signature = S::Signature>,
{
    let (pk, sk) = keypair;

    // Test regular verify
    if let Ok(sig) = sk.try_sign(data, ctx) {
        // Valid signature should verify
        assert!(pk.verify(data, &sig, ctx));

        // Modified message should not verify
        if !data.is_empty() {
            let mut modified_msg = data.to_vec();
            modified_msg[0] ^= 1;
            assert!(!pk.verify(&modified_msg, &sig, ctx));
        }

        // Modified context should not verify
        let mut modified_ctx = ctx.to_vec();
        modified_ctx.push(1);
        assert!(!pk.verify(data, &sig, &modified_ctx));
    }

    // Test hash verify
    for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
        if let Ok(sig) = sk.try_hash_sign(data, ctx, &ph) {
            // Valid signature should verify
            assert!(pk.hash_verify(data, &sig, ctx, &ph));

            // Modified message should not verify
            if !data.is_empty() {
                let mut modified_msg = data.to_vec();
                modified_msg[0] ^= 1;
                assert!(!pk.hash_verify(&modified_msg, &sig, ctx, &ph));
            }

            // Modified context should not verify
            let mut modified_ctx = ctx.to_vec();
            modified_ctx.push(1);
            assert!(!pk.hash_verify(data, &sig, &modified_ctx, &ph));

            // Different hash function should not verify
            let different_ph = match ph {
                Ph::SHA256 => Ph::SHA512,
                _ => Ph::SHA256,
            };
            assert!(!pk.hash_verify(data, &sig, ctx, &different_ph));
        }
    }
}


fuzz_target!(|data: &[u8]| {
    // Skip empty inputs
    if data.is_empty() {
        return;
    }

    // Generate static keypairs (for speed)
    let seed = [42u8; 32];
    let ml_dsa_44_keypair = ml_dsa_44::KG::keygen_from_seed(&seed);
    let ml_dsa_65_keypair = ml_dsa_65::KG::keygen_from_seed(&seed);
    let ml_dsa_87_keypair = ml_dsa_87::KG::keygen_from_seed(&seed);

    // Use first byte as context length
    let ctx_len = (data[0] as usize) % 8;
    let (ctx, msg) = data.split_at(ctx_len.min(data.len()));

    // Test all parameter sets
    fuzz_verify_for_params(msg, &ml_dsa_44_keypair, ctx);
    fuzz_verify_for_params(msg, &ml_dsa_65_keypair, ctx);
    fuzz_verify_for_params(msg, &ml_dsa_87_keypair, ctx);

    // Test serialization/deserialization
    if !msg.is_empty() {
        let (pk, sk) = &ml_dsa_65_keypair;
        if let Ok(sig) = sk.try_sign(msg, ctx) {
            // Serialize and deserialize the public key
            let pk_bytes = pk.clone().into_bytes();
            if let Ok(recovered_pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
                assert!(recovered_pk.verify(msg, &sig, ctx));
            }
        }
    }
});

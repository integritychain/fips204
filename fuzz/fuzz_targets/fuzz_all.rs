#![no_main]
use libfuzzer_sys::fuzz_target;
use fips204::ml_dsa_44::{PrivateKey, PublicKey, KG, SIG_LEN};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::pre_hash;
use rand_core::OsRng;

fuzz_target!(|data: [u8; 2560+2420+1312]| {  // sk_len + sig_len + pk_len = 6292

    // A good reference set
    let (pk_good, sk_good) = KG::try_keygen().unwrap();
    let sig_good = sk_good.try_sign(&[0u8, 1, 2, 3], &[]).unwrap();

    let sig_bad = core::array::from_fn(|i| sig_good[i] ^ data[i]);
    pk_good.verify(&[0u8, 1, 2, 3], &sig_bad, &[]);

    // Extract then deserialize a 'fuzzy' secret key
    let sk_bytes = data[0..2560].try_into().unwrap();
    let sk_fuzz = PrivateKey::try_from_bytes(sk_bytes);

    // Extract a 'fuzzy' signature
    let sig_fuzz: [u8; SIG_LEN] = data[2560..2560+2420].try_into().unwrap();

    // Extract then deserialize a 'fuzzy' public key
    let pk_bytes = data[2560+2420..2560+2420+1312].try_into().unwrap();
    let pk_fuzz = PublicKey::try_from_bytes(pk_bytes);

    // Try to use 'fuzzy' sk
    if let Ok(ref sk) = sk_fuzz {
        let sig1 = sk.try_sign(&[0u8, 1, 2, 3], &[]).unwrap();
        // ...with good pk
        let _res = pk_good.verify(&[0u8, 1, 2, 3], &sig1, &[]);
    }

    // Try to use 'fuzzy' pk
    if let Ok(ref pk) = pk_fuzz {
        let _res = pk.verify(&[0u8, 1, 2, 3], &sig_fuzz, &[]);
    }

    // Try to use 'fuzzy' sk and 'fuzzy' pk
    if let (Ok(sk), Ok(pk)) = (sk_fuzz.clone(), pk_fuzz.clone()) {
        let _sig = sk.try_sign(&[0u8, 1, 2, 3], &[]).unwrap();
        let _res = pk.verify(&[0u8, 1, 2, 3], &sig_fuzz, &[]);
    }

    if let (Ok(sk), Ok(pk)) = (sk_fuzz, pk_fuzz) {
        let oid = [&pre_hash::SHA2_256[..], &pre_hash::SHA2_512[..], &pre_hash::SHAKE_128[..]]
            [usize::from(data[0]) % 3];
        let digest = [0u8, 1, 2, 3];
        let sig = sk.try_hash_sign_with_rng(&mut OsRng, &digest, &[], oid).unwrap();
        let _res = pk.hash_verify(&digest, &sig, &[], oid);
}
});

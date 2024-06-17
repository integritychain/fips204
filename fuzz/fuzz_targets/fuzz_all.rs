#![no_main]

use libfuzzer_sys::fuzz_target;
use fips204::ml_dsa_44::{PrivateKey, PublicKey, KG, SIG_LEN};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

fuzz_target!(|data: [u8; 2560+2420+1312]| {  // sk_len + sig_len + pk_len = 6292

    // A good reference set
    let (pk_good, sk_good) = KG::try_keygen().unwrap();
    let sig_good = sk_good.try_sign(&[0u8, 1, 2, 3]).unwrap();

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
        let sig1 = sk.try_sign(&[0u8, 1, 2, 3]).unwrap();
        let sk2 = KG::gen_expanded_private(sk).unwrap();
        let sig2 = sk2.try_sign(&[4u8, 5, 6, 7]).unwrap();
        // ...with good pk
        let _res = pk_good.verify(&[0u8, 1, 2, 3], &sig1);
        let _res = pk_good.verify(&[0u8, 1, 2, 3], &sig2);
    }

    // Try to use 'fuzzy' pk
    if let Ok(ref pk) = pk_fuzz {
        let _res = pk.verify(&[0u8, 1, 2, 3], &sig_fuzz);
        let pk2 = KG::gen_expanded_public(pk).unwrap();
        let _res = pk2.verify(&[0u8, 1, 2, 3], &sig_fuzz);
        // .. with good sig
        let _res = pk2.verify(&[0u8, 1, 2, 3], &sig_good);
    }

    // Try to use 'fuzzy' sk and 'fuzzy' pk
    if let (Ok(sk), Ok(pk)) = (sk_fuzz, pk_fuzz) {
        let _sig = sk.try_sign(&[0u8, 1, 2, 3]).unwrap();
        let _res = pk.verify(&[0u8, 1, 2, 3], &sig_fuzz);
    }
});

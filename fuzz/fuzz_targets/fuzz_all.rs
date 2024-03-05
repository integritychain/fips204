#![no_main]

use libfuzzer_sys::fuzz_target;
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};

fuzz_target!(|data: [u8; 2560+2420+1312]| {  // sk_len + sig_len + pk_len = 6292

    // Deserialize a 'fuzzy' secret key
    let sk = ml_dsa_44::PrivateKey::try_from_bytes(data[0..2560].try_into().unwrap());

    // Try to use 'fuzzy' sk (a decent (?) proportion will deserialize OK)
    if let Ok(sk) = sk {
        let _sig = sk.try_sign_ct(&[0u8, 1, 2, 3]);
    }


    // Deserialize a 'fuzzy' signature
    let sig: [u8; ml_dsa_44::SIG_LEN] = data[2560..2560+2420].try_into().unwrap();

    // Try to use 'fuzzy' signature (a decent (?) proportion will deserialize OK)
    let (pk, _) = ml_dsa_44::try_keygen_vt().unwrap(); // Get a good pk
    let _v = pk.try_verify_vt(&[0u8, 1, 2, 3], &sig);


    // Deserialize a 'fuzzy' public key
    let pk = ml_dsa_44::PublicKey::try_from_bytes(data[2560+2420..2560+2420+1312].try_into().unwrap());

    // Try to use 'fuzzy' pk (a decent (?) proportion will deserialize OK)
    if let Ok(pk) = pk {
        let (_, sk) = ml_dsa_44::try_keygen_vt().unwrap();
        let sig2 = sk.try_sign_ct(&[0u8, 1, 2, 3]).unwrap();
        let _v = pk.try_verify_vt(&[0u8, 1, 2, 3], &sig2);
    }
});

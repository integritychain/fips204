use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;

// cargo flamegraph --test integration

// $ cargo test --release -- --nocapture --ignored
#[ignore]
#[test]
fn forever() {
    let mut msg = [0u8; 32];
    let mut i = 0u64;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    loop {
        rng.fill_bytes(&mut msg);
        let (pk, sk) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let sig = sk.try_sign_ct(&msg).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig);
        assert!(ver.unwrap());
        if i % 10000 == 0 {println!("So far i: {}", i)};
        i += 1;
    }
}


#[test]
fn test_44_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    for i in 0..128 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let sig = sk.try_sign_ct(&msg).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig);
        assert!(ver.unwrap())
    }
}

#[test]
fn test_65_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(456);
    for i in 0..128 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_65::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let sig = sk.try_sign_ct(&msg).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig);
        assert!(ver.unwrap())
    }
}

#[test]
fn test_87_rounds() {
    let mut msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(789);
    for i in 0..128 {
        msg[0] = i as u8;
        let (pk, sk) = ml_dsa_87::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
        let sig = sk.try_sign_ct(&msg).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig);
        assert!(ver.unwrap())
    }
}
#[test]
fn test_44_no_verif() {
    let msg = [0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    let (pk, sk) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut rng).unwrap();
    let sig = sk.try_sign_ct(&msg).unwrap();

    // Bad messages
    for i in 0..8 {
        let mut msg_bad = msg;
        msg_bad[i] ^= 0x08;
        let ver = pk.try_verify_vt(&msg_bad, &sig).unwrap();
        assert!(!ver)
    }

    // Bad secret key  (intriguing, byte 40 is 'k' which is allowed variance)
    for i in 0..8 {
        let mut sk_bad = sk.clone().into_bytes();
        sk_bad[70 + i * 10] ^= 0x08;
        let sk_bad = ml_dsa_44::PrivateKey::try_from_bytes(sk_bad).unwrap();
        let sig = sk_bad.try_sign_ct(&msg).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig).unwrap();
        assert!(!ver)
    }


    // Bad public key
    for i in 0..8 {
        let mut pk_bad = pk.clone().into_bytes();
        pk_bad[i * 10] ^= 0x08;
        let pk_bad = ml_dsa_44::PublicKey::try_from_bytes(pk_bad).unwrap();
        let ver = pk_bad.try_verify_vt(&msg, &sig).unwrap();
        assert!(!ver)
    }

    // Bad signature
    for i in 0..8 {
        let mut sig_bad = sig.clone().into_bytes();
        sig_bad[i * 10] ^= 0x08;
        let sig_bad = ml_dsa_44::Signature::try_from_bytes(sig_bad).unwrap();
        let ver = pk.try_verify_vt(&msg, &sig_bad).unwrap();
        assert!(!ver)
    }
}

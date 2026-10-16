// Negative tests for input checking.
#[cfg(feature = "ml-dsa-44")]
use fips204::ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
use fips204::ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};


// Sets coefficient j of polynomial `poly` of s1 || s2 in a serialized private key. skEncode stores
// each coefficient x as η − x in c = bitlen(2η) bits, low bits first, after ρ || K || tr.
#[allow(dead_code)]
fn set_s(sk: &mut [u8], c: usize, poly: usize, j: usize, field: u8) {
    let bit0 = 8 * 128 + (256 * poly + j) * c;
    for k in 0..c {
        let (byte, bit) = ((bit0 + k) / 8, (bit0 + k) % 8);
        sk[byte] = (sk[byte] & !(1 << bit)) | (((field >> k) & 1) << bit);
    }
}


// PrivateKey::try_from_bytes rejects an s1 or s2 coefficient outside [−η, η], which FIPS 204 §7.2
// notes a malformed key can encode. ±η stay valid. Each set checks the first s1 coefficient and the
// last s2 coefficient.
macro_rules! s_range_test {
    ($name:ident, $feature:literal, $set:ident, $eta:expr, $l:expr, $k:expr) => {
        #[test]
        #[cfg(feature = $feature)]
        fn $name() {
            let c = if $eta == 2 { 3 } else { 4 };
            let (pk, sk) = $set::KG::keygen_from_seed(&[1u8; 32]);
            let sk_bytes = sk.into_bytes();
            let msg = [2u8; 8];

            let sk = $set::PrivateKey::try_from_bytes(sk_bytes).unwrap();
            let sig = sk.try_sign_with_seed(&[3u8; 32], &msg, &[]).unwrap();
            assert!(pk.verify(&msg, &sig, &[]));

            for (poly, j) in [(0, 0), ($l + $k - 1, 255)] {
                // Stored values 0 and 2η decode to η and −η.
                for field in [0, 2 * $eta] {
                    let mut bytes = sk_bytes;
                    set_s(&mut bytes, c, poly, j, field);
                    let sk = $set::PrivateKey::try_from_bytes(bytes).unwrap();
                    assert!(sk.try_sign_with_seed(&[3u8; 32], &msg, &[]).is_ok());
                }

                // 2η + 1 and the largest stored value decode below −η.
                for field in [2 * $eta + 1, (1 << c) - 1] {
                    let mut bytes = sk_bytes;
                    set_s(&mut bytes, c, poly, j, field);
                    let res = $set::PrivateKey::try_from_bytes(bytes);
                    assert_eq!(res.err(), Some("Alg 25: s1 or s2 out of range"));
                }
            }
        }
    };
}

s_range_test!(s_range_44, "ml-dsa-44", ml_dsa_44, 2, 4, 4);
s_range_test!(s_range_65, "ml-dsa-65", ml_dsa_65, 4, 5, 6);
s_range_test!(s_range_87, "ml-dsa-87", ml_dsa_87, 2, 7, 8);


// Signing stops after the FIPS 204 Appendix C limit of 814 attempts. try_from_bytes accepts any
// t0 (every 13-bit field decodes to a legal value), so a key whose t0 does not match its other parts
// can be rejected on every attempt. Here each t0 coefficient is 2^12 or −2^12 + 1 at random; with
// this signing seed every attempt fails, and before the limit signing never returned.
#[test]
#[cfg(feature = "ml-dsa-44")]
fn sign_attempt_limit_44() {
    let (_pk, sk) = ml_dsa_44::KG::keygen_from_seed(&[9u8; 32]);
    let mut sk_bytes = sk.into_bytes();
    let t0_start = 128 + 2 * 4 * 96; // ρ || K || tr, then s1 and s2 (4 polynomials each, 3 bits)
    sk_bytes[t0_start..].fill(0);
    let mut state: u64 = 0x1234_5678_9abc_def1;
    for i in 0..(4 * 256) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let field: u32 = if state & 1 == 0 { 0 } else { 8191 }; // t0 = 2^12 − field
        for k in 0..13 {
            let bit = t0_start * 8 + i * 13 + k;
            if (field >> k) & 1 == 1 {
                sk_bytes[bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes).unwrap();
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&12u32.to_le_bytes());
    assert_eq!(
        sk.try_sign_with_seed(&seed, b"m", &[]).err(),
        Some("ML-DSA.Sign: too many attempts")
    );
    let digest = [5u8; 32];
    let res = sk.try_hash_sign_with_seed(&seed, &digest, &[], &fips204::pre_hash::SHA2_256);
    assert!(res.is_ok() || res.err() == Some("ML-DSA.Sign: too many attempts"));
}


// HashML-DSA takes the digest, not the message. For a `pre_hash` OID the digest must have that
// function's output length, so a message passed in its place is an error rather than a signature
// no other implementation verifies. Other OIDs must be DER-encoded, which fixes where the OID ends
// and the digest begins in M′.
#[test]
#[cfg(feature = "ml-dsa-44")]
fn hash_sign_digest_and_oid_checks_44() {
    use fips204::pre_hash;
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&[1u8; 32]);
    let seed = [3u8; 32];
    let ctx = b"ctx";

    for (oid, len) in [
        (&pre_hash::SHA2_224[..], 28),
        (&pre_hash::SHA2_256, 32),
        (&pre_hash::SHA2_384, 48),
        (&pre_hash::SHA2_512, 64),
        (&pre_hash::SHA2_512_224, 28),
        (&pre_hash::SHA2_512_256, 32),
        (&pre_hash::SHA3_224, 28),
        (&pre_hash::SHA3_256, 32),
        (&pre_hash::SHA3_384, 48),
        (&pre_hash::SHA3_512, 64),
        (&pre_hash::SHAKE_128, 32),
        (&pre_hash::SHAKE_256, 64),
    ] {
        let digest = [7u8; 65];
        let sig = sk.try_hash_sign_with_seed(&seed, &digest[..len], ctx, oid).unwrap();
        assert!(pk.hash_verify(&digest[..len], &sig, ctx, oid));
        for bad_len in [0, len - 1, len + 1] {
            assert_eq!(
                sk.try_hash_sign_with_seed(&seed, &digest[..bad_len], ctx, oid).err(),
                Some("HashML-DSA.Sign: digest length does not match the OID")
            );
            assert!(!pk.hash_verify(&digest[..bad_len], &sig, ctx, oid));
        }
    }

    // A message where the digest belongs (the 0.4 API hashed the message itself)
    assert!(sk.try_hash_sign_with_seed(&seed, b"hello", ctx, &pre_hash::SHA2_256).is_err());

    // OIDs that are empty or not DER
    let digest = [7u8; 32];
    let sig = sk.try_hash_sign_with_seed(&seed, &digest, ctx, &pre_hash::SHA2_256).unwrap();
    assert_eq!(
        sk.try_hash_sign_with_seed(&seed, &digest, ctx, &[]).err(),
        Some("HashML-DSA.Sign: OID is empty")
    );
    for oid in
        [&[0xffu8][..], &[0x06], &[0x06, 0x00], &[0x04, 0x01, 0x00], &pre_hash::SHA2_256[..10]]
    {
        assert_eq!(
            sk.try_hash_sign_with_seed(&seed, &digest, ctx, oid).err(),
            Some("HashML-DSA.Sign: OID is not DER encoded")
        );
        assert!(!pk.hash_verify(&digest, &sig, ctx, oid));
    }

    // The same bytes of OID || digest, split elsewhere, do not verify
    let mut shifted = vec![pre_hash::SHA2_256[10]];
    shifted.extend_from_slice(&digest);
    assert!(!pk.hash_verify(&shifted, &sig, ctx, &pre_hash::SHA2_256[..10]));

    // Another DER OID (here 1.2.3.4) takes a digest of up to 1024 bytes
    let other_oid = [0x06, 0x03, 0x2a, 0x03, 0x04];
    for len in [1, 20, 1024] {
        let digest = vec![9u8; len];
        let sig = sk.try_hash_sign_with_seed(&seed, &digest, ctx, &other_oid).unwrap();
        assert!(pk.hash_verify(&digest, &sig, ctx, &other_oid));
    }
    assert!(sk.try_hash_sign_with_seed(&seed, &[9u8; 1025], ctx, &other_oid).is_err());
}

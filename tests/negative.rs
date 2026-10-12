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

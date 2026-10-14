// This file runs the C2SP CCTV accumulated ML-DSA key generation and signature tests (CC0 1.0).
//   from: https://github.com/C2SP/CCTV/blob/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/ML-DSA/accumulated/README.md
//
// Seeds are read from one SHAKE128 instance. Each derived public key, and the deterministic
// signature of an empty message with an empty context, are written to a second SHAKE128 instance,
// and the signature must verify. The second instance's 32-byte output must match the published
// value: 10 000 iterations in release builds, 100 in debug builds. No vector data is stored.

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

macro_rules! accumulated {
    ($name:ident, $pc:ident, $feature:literal, $hash_100:literal, $hash_10k:literal) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $name() {
            use fips204::$pc;
            let (n, expected) =
                if cfg!(debug_assertions) { (100, $hash_100) } else { (10_000, $hash_10k) };
            let mut seeds = Shake128::default().finalize_xof();
            let mut acc = Shake128::default();
            for _ in 0..n {
                let mut xi = [0u8; 32];
                seeds.read(&mut xi);
                let (pk, sk) = $pc::KG::keygen_from_seed(&xi);
                let sig = sk.try_sign_with_seed(&[0u8; 32], b"", b"").unwrap();
                assert!(pk.verify(b"", &sig, b""));
                acc.update(&pk.into_bytes());
                acc.update(&sig);
            }
            let mut out = [0u8; 32];
            acc.finalize_xof().read(&mut out);
            assert_eq!(hex::encode(out), expected, "{n} iterations");
        }
    };
}

accumulated!(
    accumulated_44,
    ml_dsa_44,
    "ml-dsa-44",
    "d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4",
    "e7fd21f6a59bcba60d65adc44404bb29a7c00e5d8d3ec06a732c00a306a7d143"
);
accumulated!(
    accumulated_65,
    ml_dsa_65,
    "ml-dsa-65",
    "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199",
    "5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329"
);
accumulated!(
    accumulated_87,
    ml_dsa_87,
    "ml-dsa-87",
    "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b",
    "80a8cf39317f7d0be0e24972c51ac152bd2a3e09bc0c32ce29dd82c4e7385e60"
);

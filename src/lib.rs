#![no_std]
#![deny(clippy::pedantic, warnings, missing_docs, unsafe_code)]
// Most of the 'allow' category...
#![deny(absolute_paths_not_starting_with_crate, box_pointers, dead_code)]
#![deny(elided_lifetimes_in_paths, explicit_outlives_requirements, keyword_idents)]
#![deny(let_underscore_drop, macro_use_extern_crate, meta_variable_misuse, missing_abi)]
#![deny(non_ascii_idents, rust_2021_incompatible_closure_captures)]
#![deny(rust_2021_incompatible_or_patterns, rust_2021_prefixes_incompatible_syntax)]
#![deny(rust_2021_prelude_collisions, single_use_lifetimes, trivial_casts)]
#![deny(trivial_numeric_casts, unreachable_pub, unsafe_op_in_unsafe_fn, unstable_features)]
#![deny(unused_extern_crates, unused_import_braces, unused_lifetimes, unused_macro_rules)]
#![deny(unused_qualifications, unused_results, variant_size_differences)]
//
#![doc = include_str!("../README.md")]

// Implements FIPS 204 draft Module-Lattice-Based Digital Signature Standard.
// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf>

// TODO: Roadmap
//   1. Clean up; resolve math
//   2. Closer CT inspection
//   3. Intensive/extensive pass on documentation
//   4. Revisit/expand unit testing; consider whether to test debug statements: release-vs-test


// Functionality map per FIPS 204 draft
//
// Algorithm 1 ML-DSA.KeyGen() on page 15                 --> ml_dsa.rs
// Algorithm 2 ML-DSA.Sign(sk,M) on page 17               --> ml_dsa.rs
// Algorithm 3 ML-DSA.Verify(pk,M,σ) on page 19           --> ml_dsa.rs
// Algorithm 4 IntegerToBits(x,α) one page 20             --> (optimized away) conversion.rs
// Algorithm 5 BitsToInteger(y) on page 20                --> (optimized away) conversion.rs
// Algorithm 6 BitsToBytes(y) on page 21                  --> (optimized away) conversion.rs
// Algorithm 7 BytesToBits(z) on page 21                  --> (optimized away) conversion.rs
// Algorithm 8 CoefFromThreeBytes(b0,b1,b2) on page 21    --> conversion.rs
// Algorithm 9 CoefFromHalfByte(b) on page 22             --> conversion.rs
// Algorithm 10 SimpleBitPack(w,b) on page 22             --> conversion.rs
// Algorithm 11 BitPack(w,a,b) on page 22                 --> conversion.rs
// Algorithm 12 SimpleBitUnpack(v,b) on page 23           --> conversion.rs
// Algorithm 13 BitUnpack(v,a,b) on page 23               --> conversion.rs
// Algorithm 14 HintBitPack(h) on page 24                 --> conversion.rs
// Algorithm 15 HintBitUnpack(y) on page 24               --> conversion.rs
// Algorithm 16 pkEncode(ρ,t1) on page 25                 --> encodings.rs
// Algorithm 17 pkDecode(pk) on page 25                   --> encodings.rs
// Algorithm 18 skEncode(ρ,K,tr,s1,s2,t0) on page 26      --> encodings.rs
// Algorithm 19 skDecode(sk) on page 27                   --> encodings.rs
// Algorithm 20 sigEncode(c˜,z,h) on page 28              --> encodings.rs
// Algorithm 21 sigDecode(σ) on page 28                   --> encodings.rs
// Algorithm 22 w1Encode(w1) on page 28                   --> encodings.rs
// Algorithm 23 SampleInBall(ρ) on page 30                --> hashing.rs
// Algorithm 24 RejNTTPoly(ρ) on page 30                  --> hashing.rs
// Algorithm 25 RejBoundedPoly(ρ) on page 31              --> hashing.rs
// Algorithm 26 ExpandA(ρ) on page 31                     --> hashing.rs
// Algorithm 27 ExpandS(ρ) on page 32                     --> hashing.rs
// Algorithm 28 ExpandMask(ρ,µ) on page 32                --> hashing.rs
// Algorithm 29 Power2Round(r) on page 34                 --> high_low.rs
// Algorithm 30 Decompose(r) on page 34                   --> high_low.rs
// Algorithm 31 HighBits(r) on page 34                    --> high_low.rs
// Algorithm 32 LowBits(r) on page 35                     --> high_low.rs
// Algorithm 33 MakeHint(z,r) on page 35                  --> high_low.rs
// Algorithm 34 UseHint(h,r) on page 35                   --> high_low.rs
// Algorithm 35 NTT(w) on page 35                         --> ntt.rs
// Algorithm 36 NTT−1(wˆ) on page 27                      --> ntt.rs
// Types are in types.rs, traits are in traits.rs...
// Quite a few security parameters are used as i32 to simplify interop
// `debug_assert!()` is used for non-data checks (e.g., program structure, parameters)
// `ensure!()` is used for data-related checks at runtime (e.g., input validation)

// Note: many of the debug_assert()! and ensure()! guardrails will be removed when
// the specification is finalized and performance optimizations begin in earnest.
// The current situation is overkill.

/// The `rand_core` types are re-exported so that users of fips203 do not
/// have to worry about using the exact correct version of `rand_core`.
pub use rand_core::{CryptoRng, Error as RngError, RngCore};

mod conversion;
mod encodings;
mod hashing;
mod helpers;
mod high_low;
mod ml_dsa;
mod ntt;
mod types;

/// All functionality is covered by traits, such that consumers can utilize trait objects as desired.
pub mod traits;

// Applies across all security parameter sets
const Q: i32 = 8_380_417; // 2i32.pow(23) - 2i32.pow(13) + 1; See https://oeis.org/A234388
const ZETA: i32 = 1753; // See line 906 et al of FIPS 204
const D: u32 = 13;


// This common functionality is injected into each security parameter set module
macro_rules! functionality {
    () => {
        use crate::encodings::{pk_decode, sk_decode};
        use crate::ml_dsa;
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        const LAMBDA_DIV4: usize = LAMBDA / 4;


        // ----- 'EXTERNAL' DATA TYPES -----

        /// Correctly sized private key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
        pub type PrivateKey = crate::types::PrivateKey<SK_LEN>;

        /// Expanded private key, specific to the target security parameter set, that contains <br>
        /// precomputed elements which increase (repeated) signature performance. Implements only
        /// the [`crate::traits::Signer`] trait.
        pub type ExpandedPrivateKey = crate::types::ExpandedPrivateKey<K, L>;


        /// Correctly sized public key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
        pub type PublicKey = crate::types::PublicKey<PK_LEN>;


        /// Expanded public key, specific to the target security parameter set, that contains <br>
        /// precomputed elements which increase (repeated) verification performance. Implements only
        /// the [`crate::traits::Verifier`] traits.
        pub type ExpandedPublicKey = crate::types::ExpandedPublicKey<K, L>;


        /// Empty struct to enable `KeyGen` trait objects across security parameter sets. <br>
        /// Implements the [`crate::traits::KeyGen`] trait.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct KG(); // Arguable how useful an empty struct+trait is...


        /// Private precomputed key material derived from a `PrivateKey`. <br>
        /// Implements the [`crate::traits::Signer`] trait.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PrivatePreCompute([u8; SK_LEN]);


        // ----- PRIMARY FUNCTIONS ---

        /// Generates a public and private key pair specific to this security parameter set. <br>
        /// This function utilizes the OS default random number generator, and makes no (constant)
        /// timing assurances.
        /// # Errors
        /// Returns an error when the random number generator fails; propagates internal errors.
        /// # Examples
        /// ```rust
        /// # use std::error::Error;
        /// # fn main() -> Result<(), Box<dyn Error>> {
        /// use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
        /// use fips204::traits::{SerDes, Signer, Verifier};
        ///
        /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ///
        /// // Generate key pair and signature
        /// let (pk1, sk) = ml_dsa_44::try_keygen_vt()?;  // Generate both public and secret keys
        /// let sig1 = sk.try_sign_ct(&message)?;  // Use the secret key to generate a message signature
        /// # Ok(())}
        /// ```
        #[cfg(feature = "default-rng")]
        pub fn try_keygen_vt() -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_vt()
        }


        /// Generates a public and private key pair specific to this security parameter set. <br>
        /// This function utilizes a supplied random number generator, and makes no (constant)
        /// timing assurances.
        /// # Errors
        /// Returns an error when the random number generator fails; propagates internal errors.
        /// # Examples
        /// ```rust
        /// # use std::error::Error;
        /// # fn main() -> Result<(), Box<dyn Error>> {
        /// use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
        /// use fips204::traits::{SerDes, Signer, Verifier};
        /// use rand_chacha::rand_core::SeedableRng;
        ///
        /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
        /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        ///
        /// // Generate key pair and signature
        /// let (pk1, sk) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng)?;  // Generate both public and secret keys
        /// let sig1 = sk.try_sign_ct(&message)?;  // Use the secret key to generate a message signature
        /// # Ok(())}
        /// ```
        pub fn try_keygen_with_rng_vt(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_with_rng_vt(rng)
        }


        impl KeyGen for KG {
            type ExpandedPrivateKey = ExpandedPrivateKey;
            type ExpandedPublicKey = ExpandedPublicKey;
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;

            fn try_keygen_with_rng_vt(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<K, L, PK_LEN, SK_LEN>(rng, ETA)?;
                Ok((PublicKey { 0: pk }, PrivateKey { 0: sk }))
            }

            fn gen_expanded_private_vt(
                sk: &PrivateKey,
            ) -> Result<Self::ExpandedPrivateKey, &'static str> {
                let esk = ml_dsa::sign_start(ETA, &sk.0)?;
                Ok(esk)
            }

            fn gen_expanded_public_vt(
                pk: &PublicKey,
            ) -> Result<Self::ExpandedPublicKey, &'static str> {
                let epk = ml_dsa::verify_start(&pk.0)?;
                Ok(epk)
            }
        }


        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];

            fn try_sign_with_rng_ct(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                let esk = ml_dsa::sign_start(ETA, &self.0)?;
                let sig = ml_dsa::sign_finish::<K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN>(
                    rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &esk, message,
                )?;
                Ok(sig)
            }
        }


        impl Signer for ExpandedPrivateKey {
            type Signature = [u8; SIG_LEN];

            fn try_sign_with_rng_ct(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                let sig = ml_dsa::sign_finish::<K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN>(
                    rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message,
                )?;
                Ok(sig)
            }
        }


        impl Verifier for PublicKey {
            type Signature = [u8; SIG_LEN];

            fn try_verify_vt(
                &self, message: &[u8], sig: &Self::Signature,
            ) -> Result<bool, &'static str> {
                let epk = ml_dsa::verify_start(&self.0)?;
                ml_dsa::verify_finish::<K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &epk, &message, &sig,
                )
            }
        }

        impl Verifier for ExpandedPublicKey {
            type Signature = [u8; SIG_LEN];

            fn try_verify_vt(
                &self, message: &[u8], sig: &Self::Signature,
            ) -> Result<bool, &'static str> {
                ml_dsa::verify_finish::<K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig,
                )
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];

            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                let _ = pk_decode::<K, PK_LEN>(&pk)?; //.map_err(|_e| "Public key deserialization failed");
                Ok(PublicKey { 0: pk })
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];

            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                let _ = sk_decode::<K, L, SK_LEN>(ETA, &sk)?; //.map_err(|_e| "Private key deserialization failed");
                Ok(PrivateKey { 0: sk })
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }
    };
}


// Regarding private key sizes, see https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/EKoI0u_PuOw/m/b02zPvomBAAJ


/// Functionality for the **ML-DSA-44** security parameter set. This includes specific sizes for the
/// public key, secret key, and signature along with a number of internal constants. The ML-DSA-44
/// parameter set is claimed to be in security strength category 2.
///
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen_vt`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    use super::Q;
    const TAU: i32 = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 2i32.pow(17);
    const GAMMA2: i32 = (Q - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const BETA: i32 = TAU * ETA;
    const OMEGA: i32 = 80;
    /// Private (secret) key length in bytes.
    pub const SK_LEN: usize = 2560;
    /// Public key length in bytes.
    pub const PK_LEN: usize = 1312;
    /// Signature length in bytes.
    pub const SIG_LEN: usize = 2420;

    functionality!();
}


/// Functionality for the **ML-DSA-65** security parameter set. This includes specific sizes for the
/// public key, secret key, and signature along with a number of internal constants. The ML-DSA-65
/// parameter set is claimed to be in security strength category 3.
///
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen_vt`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    use super::Q;
    const TAU: i32 = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 2i32.pow(19);
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const BETA: i32 = TAU * ETA;
    const OMEGA: i32 = 55;
    /// Private (secret) key length in bytes.
    pub const SK_LEN: usize = 4032;
    /// Public key length in bytes.
    pub const PK_LEN: usize = 1952;
    /// Signature length in bytes.
    pub const SIG_LEN: usize = 3309;

    functionality!();
}


/// Functionality for the **ML-DSA-87** security parameter set. This includes specific sizes for the
/// public key, secret key, and signature along with a number of internal constants. The ML-DSA-87
/// parameter set is claimed to be in security strength category 5.
///
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen_vt`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    use super::Q;
    const TAU: i32 = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 2i32.pow(19);
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const BETA: i32 = TAU * ETA;
    const OMEGA: i32 = 75;
    /// Private (secret) key length in bytes.
    pub const SK_LEN: usize = 4896;
    /// Public key length in bytes.
    pub const PK_LEN: usize = 2592;
    /// Signature length in bytes.
    pub const SIG_LEN: usize = 4627;

    functionality!();
}

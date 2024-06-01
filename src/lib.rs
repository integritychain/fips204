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

// Functionality map per draft FIPS 204
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

// Note that debug! statements enforce correct program construction and are not involved
// in any operational dataflow (so are good fuzz targets). The ensure! statements implement
// conservative dataflow validation. Separately, functions are only generic over security
// parameters that are directly involved in memory allocation (on the stack). Some coding
// oddities are driven by the fact that Rust doesn't currently do well with arithmetic on
// generic parameters.

// Note that the `CTEST` generic parameter supports constant-time measurements by dudect. This
// is done by carefully removing timing variability of non-secret data (such as the rejection
// sampling of hash derived from rho). All normal crate functionality has this set to `false`
// except for the single function (per namespace) `dudect_keygen_sign_with_rng()` which is only
// exposed when the non-default `dudect` feature is enabled.

/// The `rand_core` types are re-exported so that users of fips204 do not
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
const Q: i32 = 8_380_417; // 2^23 - 2^13 + 1 = 0x7FE001; See https://oeis.org/A234388
const ZETA: i32 = 1753; // See line 906 et al of FIPS 204
const D: u32 = 13; // See table 1 page 13 second row


// This common functionality is injected into each security parameter set namespace, and in
// general is a lightweight wrapper into the ml_dsa functions.
macro_rules! functionality {
    () => {
        use crate::encodings::{pk_decode, sk_decode};
        use crate::helpers::bit_length;
        use crate::ml_dsa;
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        const LAMBDA_DIV4: usize = LAMBDA / 4;
        const CTILDE_LEN: usize = 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1);
        const CTEST: bool = false; // when true, the logid goes into CT test mode

        // ----- 'EXTERNAL' DATA TYPES -----

        /// Correctly sized private key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
        pub type PrivateKey = crate::types::PrivateKey<SK_LEN>;

        /// Expanded private key, specific to the target security parameter set, that contains <br>
        /// precomputed elements which increase (repeated) signature performance. Implements only
        /// the [`crate::traits::Signer`] trait. Derived from the `PrivateKey`.
        pub type ExpandedPrivateKey = crate::types::ExpandedPrivateKey<K, L>;

        /// Correctly sized public key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
        pub type PublicKey = crate::types::PublicKey<PK_LEN>;

        /// Expanded public key, specific to the target security parameter set, that contains <br>
        /// precomputed elements which increase (repeated) verification performance. Implements only
        /// the [`crate::traits::Verifier`] traits. Derived from the `PublicKey`.
        pub type ExpandedPublicKey = crate::types::ExpandedPublicKey<K, L>;

        /// Empty struct to enable `KeyGen` trait objects across security parameter sets. <br>
        /// Implements the [`crate::traits::KeyGen`] trait.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct KG(); // Arguable how useful an empty struct+trait is...

        // ----- PRIMARY FUNCTIONS ---

        /// Generates a public and private key pair specific to this security parameter set.
        /// This function utilizes the **OS default** random number generator. This function operates
        /// in constant-time relative to secret data (which specifically excludes the OS random
        /// number generator internals, the `rho` value stored in the public key, and the hash-derived
        /// `rho_prime` value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values).
        /// # Errors
        /// Returns an error when the random number generator fails.
        /// # Examples
        /// ```rust
        /// # use std::error::Error;
        /// # fn main() -> Result<(), Box<dyn Error>> {
        /// # #[cfg(all(feature = "ml-dsa-44", feature = "default-rng"))] {
        /// use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
        /// use fips204::traits::{SerDes, Signer, Verifier};
        ///
        /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ///
        /// // Generate key pair and signature
        /// let (pk1, sk) = ml_dsa_44::try_keygen()?; // Generate both public and secret keys
        /// let sig1 = sk.try_sign(&message)?; // Use the secret key to generate a message signature
        /// # }
        /// # Ok(())}
        /// ```
        #[cfg(feature = "default-rng")]
        pub fn try_keygen() -> Result<(PublicKey, PrivateKey), &'static str> { KG::try_keygen() }


        /// Generates a public and private key pair specific to this security parameter set.
        /// This function utilizes the **provided** random number generator. This function operates
        /// in constant-time relative to secret data (which specifically excludes the provided random
        /// number generator internals, the `rho` value stored in the public key, and the hash-derived
        /// `rho_prime` value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values).
        /// # Errors
        /// Returns an error when the random number generator fails.
        /// # Examples
        /// ```rust
        /// # use std::error::Error;
        /// # fn main() -> Result<(), Box<dyn Error>> {
        /// # #[cfg(feature = "ml-dsa-44")] {
        /// use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
        /// use fips204::traits::{SerDes, Signer, Verifier};
        /// use rand_chacha::rand_core::SeedableRng;
        ///
        /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
        /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        ///
        /// // Generate key pair and signature
        /// let (pk1, sk) = ml_dsa_44::try_keygen_with_rng(&mut rng)?;  // Generate both public and secret keys
        /// let sig1 = sk.try_sign_with_rng(&mut rng, &message)?;  // Use the secret key to generate a message signature
        /// # }
        /// # Ok(())}
        /// ```
        pub fn try_keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_with_rng(rng)
        }


        impl KeyGen for KG {
            type ExpandedPrivateKey = ExpandedPrivateKey;
            type ExpandedPublicKey = ExpandedPublicKey;
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;

            fn try_keygen_with_rng(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<CTEST, K, L, PK_LEN, SK_LEN>(rng, ETA)?;
                Ok((PublicKey { 0: pk }, PrivateKey { 0: sk }))
            }

            fn gen_expanded_private(
                sk: &PrivateKey,
            ) -> Result<Self::ExpandedPrivateKey, &'static str> {
                let esk = ml_dsa::sign_start::<CTEST, K, L, SK_LEN>(ETA, &sk.0)?;
                Ok(esk)
            }

            fn gen_expanded_public(
                pk: &PublicKey,
            ) -> Result<Self::ExpandedPublicKey, &'static str> {
                let epk = ml_dsa::verify_start(&pk.0)?;
                Ok(epk)
            }
        }


        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];

            fn try_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                let esk = ml_dsa::sign_start::<CTEST, K, L, SK_LEN>(ETA, &self.0)?;
                let sig =
                    ml_dsa::sign_finish::<CTEST, CTILDE_LEN, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN>(
                        rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &esk, message,
                    )?;
                Ok(sig)
            }
        }


        impl Signer for ExpandedPrivateKey {
            type Signature = [u8; SIG_LEN];

            fn try_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                let sig =
                    ml_dsa::sign_finish::<CTEST, CTILDE_LEN, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN>(
                        rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message,
                    )?;
                Ok(sig)
            }
        }


        impl Verifier for PublicKey {
            type Signature = [u8; SIG_LEN];

            fn try_verify(
                &self, message: &[u8], sig: &Self::Signature,
            ) -> Result<bool, &'static str> {
                let epk = ml_dsa::verify_start(&self.0)?;
                ml_dsa::verify_finish::<CTILDE_LEN, K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &epk, &message, &sig,
                )
            }
        }


        impl Verifier for ExpandedPublicKey {
            type Signature = [u8; SIG_LEN];

            fn try_verify(
                &self, message: &[u8], sig: &Self::Signature,
            ) -> Result<bool, &'static str> {
                ml_dsa::verify_finish::<CTILDE_LEN, K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig,
                )
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];

            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                let _unused =
                    pk_decode::<K, PK_LEN>(&pk).map_err(|_e| "Public key deserialization failed");
                Ok(PublicKey { 0: pk })
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];

            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                let _unused = sk_decode::<K, L, SK_LEN>(ETA, &sk)
                    .map_err(|_e| "Private key deserialization failed");
                Ok(PrivateKey { 0: sk })
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }

        // ----- SUPPORT FOR DUDECT CONSTANT TIME MEASUREMENTS ---

        /// This function supports the dudect constant-time measurement framework, and
        /// is only exposed with the `dudect` feature is enabled.
        /// # Errors
        /// Returns an error when the random number generator fails; propagates internal errors.
        #[cfg(feature = "dudect")]
        pub fn dudect_keygen_sign_with_rng(
            rng: &mut impl CryptoRngCore, message: &[u8],
        ) -> Result<[u8; SIG_LEN], &'static str> {
            let (_pk, sk) = ml_dsa::key_gen::<true, K, L, PK_LEN, SK_LEN>(rng, ETA)?;
            let esk = ml_dsa::sign_start::<true, K, L, SK_LEN>(ETA, &sk)?;
            let sig = ml_dsa::sign_finish::<true, CTILDE_LEN, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN>(
                rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &esk, message,
            )?;
            Ok(sig)
        }
    };
}

// Regarding private key sizes, see https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/EKoI0u_PuOw/m/b02zPvomBAAJ


/// Functionality for the **ML-DSA-44** security parameter set. This includes specific sizes for the
/// public key, secret key, and signature along with a number of internal constants. The ML-DSA-44
/// parameter set is claimed to be in security strength category 2.
///
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    use super::Q;
    const TAU: i32 = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 1 << 17;
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
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    use super::Q;
    const TAU: i32 = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 1 << 19;
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
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with the `Signature` byte array.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    use super::Q;
    const TAU: i32 = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 1 << 19;
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

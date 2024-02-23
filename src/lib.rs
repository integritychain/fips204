#![cfg_attr(not(test), no_std)]
#![deny(clippy::pedantic)]
#![deny(warnings)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
// To remove...need to rework element+math
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::similar_names)]

// Roadmap
//  1. types -> types.rs
//  2. github actions (init cargo deny)
//  3. Refine LAMBDA
//  4. Resolve/remove precompute signing
//  5. Clean up remaining rem_euclid instances
//  6. More robust unit testing
//  7. infinity_norm() -> check_infinity_norm() w/ early exit
//  8. Remove blanket clippy allows

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

const QI: i32 = 8_380_417; // 2i32.pow(23) - 2i32.pow(13) + 1; See https://oeis.org/A234388
const QU: u32 = QI as u32; // 2u32.pow(23) - 2u32.pow(13) + 1;
const ZETA: i32 = 1753; // See line 906 et al
const D: u32 = 13;


// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        use crate::encodings::{pk_decode, sig_decode, sk_decode};
        use crate::ml_dsa;
        use crate::traits::{KeyGen, PreGen, SerDes, Signer, Verifier};
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};


        // ----- 'EXTERNAL' DATA TYPES -----

        /// Correctly sized private key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Signer`], [`crate::traits::SerDes`], and
        /// [`crate::traits::PreGen`] traits.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey([u8; SK_LEN]);


        /// Correctly sized public key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PublicKey([u8; PK_LEN]);


        /// Correctly sized signature specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::SerDes`] trait.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct Signature([u8; SIG_LEN]);


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
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;

            fn try_keygen_with_rng_vt(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<K, L, PK_LEN, SK_LEN>(rng, ETA)?;
                Ok((PublicKey(pk), PrivateKey(sk)))
            }
        }


        impl Signer for PrivateKey {
            type Signature = Signature;

            fn try_sign_with_rng_ct(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Signature, &'static str> {
                let sig = ml_dsa::sign::<K, L, LAMBDA, SIG_LEN, SK_LEN>(
                    rng, BETA, ETA, GAMMA1, GAMMA2, OMEGA, TAU, &self.0, message,
                )?;
                Ok(Signature(sig))
            }
        }


        impl PreGen for PrivateKey {
            type PreCompute = PrivatePreCompute;

            fn gen_precompute(&self) -> PrivatePreCompute {
                PrivatePreCompute(self.clone().into_bytes())
            }
        }


        impl Signer for PrivatePreCompute {
            type Signature = Signature;

            fn try_sign_with_rng_ct(
                &self, rng: &mut impl CryptoRngCore, message: &[u8],
            ) -> Result<Signature, &'static str> {
                let sig = ml_dsa::sign::<K, L, LAMBDA, SIG_LEN, SK_LEN>(
                    rng, BETA, ETA, GAMMA1, GAMMA2, OMEGA, TAU, &self.0, message,
                )?;
                Ok(Signature(sig))
            }
        }


        impl Verifier for PublicKey {
            type Signature = Signature;

            fn try_verify_vt(&self, message: &[u8], sig: &Signature) -> Result<bool, &'static str> {
                ml_dsa::verify::<K, L, LAMBDA, PK_LEN, SIG_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self.0, &message, &sig.0,
                )
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for Signature {
            type ByteArray = [u8; SIG_LEN];

            fn try_from_bytes(sig: Self::ByteArray) -> Result<Self, &'static str> {
                let _ = sig_decode::<K, L, LAMBDA>(GAMMA1, OMEGA, &sig)?; //.map_err(|_e| "Signature deserialization failed");
                Ok(Signature(sig))
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];

            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                let _ = pk_decode::<K, PK_LEN>(&pk)?; //.map_err(|_e| "Public key deserialization failed");
                Ok(PublicKey(pk))
            }

            fn into_bytes(self) -> Self::ByteArray { self.0 }
        }


        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];

            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                let _ = sk_decode::<{ D as usize }, K, L, SK_LEN>(ETA, &sk)?; //.map_err(|_e| "Private key deserialization failed");
                Ok(PrivateKey(sk))
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
/// **2)** All three (`PrivateKey`, `PublicKey`and `Signature`) structs implement the [`traits::SerDes`]
/// trait. The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the
/// latter two structs into byte-arrays for transmission with the message. Upon receipt, the remote
/// party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize these byte-arrays
/// into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with its [`ml_dsa_44::Signature`] struct.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    use super::{D, QU};
    const TAU: u32 = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: u32 = 2u32.pow(17);
    const GAMMA2: u32 = (QU - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: u32 = 2;
    const BETA: u32 = TAU * ETA;
    const OMEGA: u32 = 80;
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
/// **2)** All three (`PrivateKey`, `PublicKey`and `Signature`) structs implement the [`traits::SerDes`]
/// trait. The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the
/// latter two structs into byte-arrays for transmission with the message. Upon receipt, the remote
/// party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize these byte-arrays
/// into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with its [`ml_dsa_44::Signature`] struct.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    use super::{D, QU};
    const TAU: u32 = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: u32 = 2u32.pow(19);
    const GAMMA2: u32 = (QU - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: u32 = 4;
    const BETA: u32 = TAU * ETA;
    const OMEGA: u32 = 55;
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
/// **2)** All three (`PrivateKey`, `PublicKey`and `Signature`) structs implement the [`traits::SerDes`]
/// trait. The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the
/// latter two structs into byte-arrays for transmission with the message. Upon receipt, the remote
/// party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize these byte-arrays
/// into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`ml_dsa_44::PublicKey`] struct to verify the message with its [`ml_dsa_44::Signature`] struct.
///
/// See the top-level [crate] documentation for example code that implements the above flow.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    use super::{D, QU};
    const TAU: u32 = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: u32 = 2u32.pow(19);
    const GAMMA2: u32 = (QU - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: u32 = 2;
    const BETA: u32 = TAU * ETA;
    const OMEGA: u32 = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;

    functionality!();
}

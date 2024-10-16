#![no_std]
#![deny(clippy::pedantic, warnings, missing_docs, unsafe_code)]
// Almost all of the 'allow' category...
#![deny(absolute_paths_not_starting_with_crate, dead_code)]
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


// TODO Roadmap
//  1. Improve docs on first/last few algorithms
//  2. Always more testing...

// Implements FIPS 204 Module-Lattice-Based Digital Signature Standard.
// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

// Functionality map per FIPS 204
//
// Algorithm 1 ML-DSA.KeyGen() on page 17                   --> lib.rs
// Algorithm 2 ML-DSA.Sign(sk,M,ctx) on page 18             --> lib.rs
// Algorithm 3 ML-DSA.Verify(pk,M,s,ctx) on page 18         --> lib.rs
// Algorithm 4 HashML-DSA.Sign(sk,M,ctx,PH) on page 20      --> lib.rs
// Algorithm 5 HashML-DSA.Verify(sk,M,s,ctx,PH) on page 21  --> lib.rs
// Algorithm 6 ML-DSA.KeyGen_internal(x) on page 23         --> (refactored) ml_dsa.rs
// Algorithm 7 ML-DSA.Sign_internal(sk,M',rnd) on page 25   --> (refactored) ml_dsa.rs
// Algorithm 8 ML-DSA.Verify_internal(pk,M',s) on page 27   --> (refactored) ml_dsa.rs
// Algorithm 9 IntegerToBits(x,a) one page 28               --> (optimized away) conversion.rs
// Algorithm 10 BitsToInteger(y,a) on page 28               --> (optimized away) conversion.rs
// Algorithm 11 IntegerToBytes(x,a) on page 28              --> (optimized away) conversion.rs
// Algorithm 12 BitsToBytes(y) on page 29                   --> (optimized away) conversion.rs
// Algorithm 13 BytesToBits(z) on page 29                   --> (optimized away) conversion.rs
// Algorithm 14 CoefFromThreeBytes(b0,b1,b2) on page 29     --> conversion.rs
// Algorithm 15 CoefFromHalfByte(b) on page 30              --> conversion.rs
// Algorithm 16 SimpleBitPack(w,b) on page 30               --> conversion.rs
// Algorithm 17 BitPack(w,a,b) on page 30                   --> conversion.rs
// Algorithm 18 SimpleBitUnpack(v,b) on page 31             --> conversion.rs
// Algorithm 19 BitUnpack(v,a,b) on page 31                 --> conversion.rs
// Algorithm 20 HintBitPack(h) on page 32                   --> conversion.rs
// Algorithm 21 HintBitUnpack(y) on page 32                 --> conversion.rs
// Algorithm 22 pkEncode(ρ,t1) on page 33                   --> encodings.rs
// Algorithm 23 pkDecode(pk) on page 33                     --> encodings.rs
// Algorithm 24 skEncode(ρ,K,tr,s1,s2,t0) on page 34        --> encodings.rs
// Algorithm 25 skDecode(sk) on page 34                     --> encodings.rs
// Algorithm 26 sigEncode(c˜,z,h) on page 35                --> encodings.rs
// Algorithm 27 sigDecode(σ) on page 35                     --> encodings.rs
// Algorithm 28 w1Encode(w1) on page 35                     --> encodings.rs
// Algorithm 29 SampleInBall(ρ) on page 36                  --> hashing.rs
// Algorithm 30 RejNTTPoly(ρ) on page 37                    --> hashing.rs
// Algorithm 31 RejBoundedPoly(ρ) on page 37                --> hashing.rs
// Algorithm 32 ExpandA(ρ) on page 38                       --> hashing.rs
// Algorithm 33 ExpandS(ρ) on page 38                       --> hashing.rs
// Algorithm 34 ExpandMask(ρ,µ) on page 38                  --> hashing.rs
// Algorithm 35 Power2Round(r) on page 40                   --> high_low.rs
// Algorithm 36 Decompose(r) on page 40                     --> high_low.rs
// Algorithm 37 HighBits(r) on page 40                      --> high_low.rs
// Algorithm 38 LowBits(r) on page 41                       --> high_low.rs
// Algorithm 39 MakeHint(z,r) on page 41                    --> high_low.rs
// Algorithm 40 UseHint(h,r) on page 41                     --> high_low.rs
// Algorithm 41 NTT(w) on page 43                           --> ntt.rs
// Algorithm 42 NTT−1(wˆ) on page 44                        --> ntt.rs
// Algorithm 43 BitRev8(m) on page 44                       --> helpers.rs
// Algorithm 44 AddNTT(a,b)̂ on page 45                      --> helpers.rs
// Algorithm 45 MultiplyNTT(a,b)̂ on page 45                 --> helpers.rs
// Algorithm 46 AddVectorNTT(v,w) on page 45                --> helpers.rs
// Algorithm 47 ScalarVectorNTT(c,v)̂ on page 46             --> helpers.rs
// Algorithm 48 MatrixVectorNTT(M,v) on page 46             --> helpers.rs
// Algorithm 49 MontgomeryReduce(a) on page 50              --> helpers.rs
// Types are in types.rs, traits are in traits.rs...

// Note that debug! statements enforce correct program construction and are not involved
// in any operational dataflow (so are good fuzz targets). The ensure! statements implement
// conservative dataflow validation. Separately, functions are only generic over security
// parameters that are directly involved in memory allocation (on the stack). Some coding
// oddities are driven by 'clippy pedantic' and the fact that Rust doesn't currently do well
// with arithmetic on generic parameters.

// Note that the `CTEST` generic parameter supports constant-time measurements by dudect. This
// is done by minimally removing timing variability of non-secret data (such as the rejection
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
pub use crate::types::Ph;

// Applies across all security parameter sets
const Q: i32 = 8_380_417; // 2^23 - 2^13 + 1 = 0x7FE001; table 1 page 15 first row
const ZETA: i32 = 1753; // See section 2.5 of FIPS 204; table 1 page 15 second row
const D: u32 = 13; // See table 1 page 15 third row


// This common functionality is injected into each security parameter set namespace, and is
// largely a lightweight wrapper into the ml_dsa functions.
macro_rules! functionality {
    () => {
        use crate::hashing::hash_message;
        use crate::helpers::{bit_length, ensure};
        use crate::ml_dsa;
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use crate::types::Ph;
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        const LAMBDA_DIV4: usize = LAMBDA / 4;
        const W1_LEN: usize = 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1);
        const CTEST: bool = false; // When true, the logic goes into CT test mode


        // ----- 'EXTERNAL' DATA TYPES -----

        /// Empty struct to enable `KeyGen` trait objects across security parameter
        /// sets. Implements the [`crate::traits::KeyGen`] trait.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct KG();

        /// Private key specific to the target security parameter set that contains
        /// precomputed elements which improves signature performance.
        ///
        /// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
        //  #[derive(Zeroize, ZeroizeOnDrop)] is implemented on the underlying type.
        pub type PrivateKey = crate::types::PrivateKey<K, L>;

        /// Public key specific to the target security parameter set that contains
        /// precomputed elements which improves verification performance.
        ///
        /// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
        //  #[derive(Zeroize, ZeroizeOnDrop)] is implemented on the underlying type.
        pub type PublicKey = crate::types::PublicKey<K, L>;

        // Note: (public) Signature is just a vanilla fixed-size byte array


        // ----- PRIMARY FUNCTIONS ---

        /// Algorithm 1: Generates a public and private key pair specific to this security
        /// parameter set.
        ///
        /// This function utilizes the **default OS ** random number generator. It operates
        /// in constant-time relative to secret data (which specifically excludes the
        /// random number generator internals, the `rho` value stored in the public key,
        /// and the hash-derived `rho_prime` value that is rejection-sampled/expanded into
        /// the internal `s_1` and `s_2` values).
        /// # Errors
        /// Returns an error if the random number generator fails.
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
        /// let (pk1, sk) = ml_dsa_44::try_keygen()?;  // Generate both public and secret keys
        /// let sig1 = sk.try_sign(&message, &[0])?;  // Use the secret key to generate a message signature
        /// # }
        /// # Ok(())}
        /// ```
        #[cfg(feature = "default-rng")]
        pub fn try_keygen() -> Result<(PublicKey, PrivateKey), &'static str> { KG::try_keygen() }


        /// Algorithm 1: Generates a public and private key pair specific to this security
        /// parameter set.
        ///
        /// This function utilizes the **provided** random number generator. It operates
        /// in constant-time relative to secret data (which specifically excludes the
        /// random number generator internals, the `rho` value stored in the public key,
        /// and the hash-derived `rho_prime` value that is rejection-sampled/expanded into
        /// the internal `s_1` and `s_2` values).
        /// # Errors
        /// Returns an error if the random number generator fails.
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
        /// let sig1 = sk.try_sign_with_rng(&mut rng, &message, &[0])?;  // Use the secret key to generate a message signature
        /// # }
        /// # Ok(())}
        /// ```
        pub fn try_keygen_with_rng(rng: &mut impl CryptoRngCore) -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_with_rng(rng)
        }


        impl KeyGen for KG {
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;


            // Algorithm 1 in KeyGen trait
            fn try_keygen_with_rng(rng: &mut impl CryptoRngCore) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<CTEST, K, L, PK_LEN, SK_LEN>(rng, ETA)?;
                Ok((pk, sk))
            }


            fn keygen_from_seed(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey) {
                let (pk, sk) = ml_dsa::key_gen_internal::<CTEST, K, L, PK_LEN, SK_LEN>(ETA, xi);
                (pk, sk)
            }
        }


        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];
            type PublicKey = PublicKey;


            // Algorithm 2 in Signer trait.
            fn try_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                ensure!(ctx.len() < 256, "ML-DSA.Sign: ctx too long");
                let sig = ml_dsa::sign::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                    rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message, ctx, &[], &[], false
                )?;
                Ok(sig)
            }


            // Algorithm 4 in Signer trait.
            fn try_hash_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8], ph: &Ph,
            ) -> Result<Self::Signature, &'static str> {
                ensure!(ctx.len() < 256, "HashML-DSA.Sign: ctx too long");
                let mut phm = [0u8; 64];  // hashers don't all play well with each other
                let (oid, phm_len) = hash_message(message, ph, &mut phm);
                let sig = ml_dsa::sign::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                    rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message, ctx, &oid, &phm[0..phm_len], false
                )?;
                Ok(sig)
            }


            // Documented in traits.rs
            #[allow(clippy::cast_lossless)]
            fn get_public_key(&self) -> Self::PublicKey {
                use crate::types::{R, T};
                use crate::ntt::{inv_ntt, ntt};
                use crate::helpers::{add_vector_ntt, mat_vec_mul, full_reduce32, mont_reduce};
                use crate::high_low::power2round;
                use crate::helpers::to_mont;
                use crate::D;

                // TODO: refactor
                let PrivateKey {rho, cap_k: _, tr, s_hat_1_mont, s_hat_2_mont, t_hat_0_mont, cap_a_hat} = &self;
                let s_1: [R; L] = inv_ntt(&core::array::from_fn(|l| T(core::array::from_fn(|n| full_reduce32(mont_reduce(s_hat_1_mont[l].0[n] as i64))))));
                let s_1: [R; L] = core::array::from_fn(|l| R(core::array::from_fn(|n| if s_1[l].0[n] > (Q >> 2) {s_1[l].0[n] - Q} else {s_1[l].0[n]})));
                let s_2: [R; K] = inv_ntt(&core::array::from_fn(|k| T(core::array::from_fn(|n| full_reduce32(mont_reduce(s_hat_2_mont[k].0[n] as i64))))));
                let s_2: [R; K] = core::array::from_fn(|k| R(core::array::from_fn(|n| if s_2[k].0[n] > (Q >> 2) {s_2[k].0[n] - Q} else {s_2[k].0[n]})));
                let t_0: [R; K] = inv_ntt(&core::array::from_fn(|k| T(core::array::from_fn(|n| full_reduce32(mont_reduce(t_hat_0_mont[k].0[n] as i64))))));
                let sk_t_0: [R; K] = core::array::from_fn(|k| R(core::array::from_fn(|n| if t_0[k].0[n] > (Q / 2) {t_0[k].0[n] - Q} else {t_0[k].0[n]})));

                // 5: t ← NTT−1(cap_a_hat ◦ NTT(s_1)) + s_2    ▷ Compute t = As1 + s2
                let t: [R; K] = {
                    let s_1_hat: [T; L] = ntt(&s_1);
                    let as1_hat: [T; K] = mat_vec_mul(&cap_a_hat, &s_1_hat);
                    let t_not_reduced: [R; K] = add_vector_ntt(&inv_ntt(&as1_hat), &s_2);
                    core::array::from_fn(|k| R(core::array::from_fn(|n| full_reduce32(t_not_reduced[k].0[n]))))
                };

                // 6: (t_1, t_0) ← Power2Round(t, d)    ▷ Compress t
                let (t_1, pk_t_0): ([R; K], [R; K]) = power2round(&t);
                debug_assert_eq!(sk_t_0, pk_t_0); // fuzz target

                // 7: pk ← pkEncode(ρ, t_1)
                //let pk: [u8; PK_LEN] = pk_encode(rho, &t_1);
                // the last term of:
                // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
                let t1_hat_mont: [T; K] = to_mont(&ntt(&t_1));
                let t1_d2_hat_mont: [T; K] = to_mont(&core::array::from_fn(|k| {
                    T(core::array::from_fn(|n| mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D)))
                }));
                let pk = PublicKey { rho: *rho, cap_a_hat: cap_a_hat.clone(), tr: *tr, t1_d2_hat_mont};

                // 10: return pk
                pk
            }
        }


        impl Verifier for PublicKey {
            type Signature = [u8; SIG_LEN];

            // Algorithm 3 in Verifier trait.
            fn verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8]) -> bool {
                let Ok(res) = ml_dsa::verify::<K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig, ctx, &[], &[], false
                ) else {
                    return false;
                };
                res
            }

            // Algorithm 5 in Verifier trait.
            fn hash_verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8], ph: &Ph) -> bool {
                if ctx.len() > 255 {
                    return false;
                };
                let mut phm = [0u8; 64];  // hashers don't all play well with each other
                let (oid, phm_len) = hash_message(message, ph, &mut phm);
                let Ok(res) = ml_dsa::verify::<K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig, ctx, &oid, &phm[0..phm_len], false
                ) else {
                    return false;
                };
                res
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];


            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                let esk = ml_dsa::expand_private::<CTEST, K, L, SK_LEN>(ETA, &sk)?;
                Ok(esk)
            }


            #[allow(clippy::cast_lossless)]
            fn into_bytes(self) -> Self::ByteArray {
                use crate::types::{R, T};
                use crate::helpers::mont_reduce;
                use crate::helpers::full_reduce32;
                use crate::ntt::inv_ntt;

                // TODO: refactor
                let PrivateKey {rho, cap_k, tr, s_hat_1_mont, s_hat_2_mont, t_hat_0_mont, ..} = &self;
                let s_1: [R; L] = inv_ntt(&core::array::from_fn(|l| T(core::array::from_fn(|n| full_reduce32(mont_reduce(s_hat_1_mont[l].0[n] as i64))))));
                let s_1: [R; L] = core::array::from_fn(|l| R(core::array::from_fn(|n| if s_1[l].0[n] > (Q >> 2) {s_1[l].0[n] - Q} else {s_1[l].0[n]})));
                let s_2: [R; K] = inv_ntt(&core::array::from_fn(|k| T(core::array::from_fn(|n| full_reduce32(mont_reduce(s_hat_2_mont[k].0[n] as i64))))));
                let s_2: [R; K] = core::array::from_fn(|k| R(core::array::from_fn(|n| if s_2[k].0[n] > (Q >> 2) {s_2[k].0[n] - Q} else {s_2[k].0[n]})));
                let t_0: [R; K] = inv_ntt(&core::array::from_fn(|k| T(core::array::from_fn(|n| full_reduce32(mont_reduce(t_hat_0_mont[k].0[n] as i64))))));
                let t_0: [R; K] = core::array::from_fn(|k| R(core::array::from_fn(|n| if t_0[k].0[n] > (Q / 2) {t_0[k].0[n] - Q} else {t_0[k].0[n]})));
                let sk = crate::encodings::sk_encode::<K, L, SK_LEN>(ETA, rho, cap_k, tr, &s_1, &s_2, &t_0);
                sk
            }
        }


        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];


            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                let epk = ml_dsa::expand_public(&pk)?;
                Ok(epk)

            }


            #[allow(clippy::cast_lossless)]
            fn into_bytes(self) -> Self::ByteArray {
                use crate::types::{R, T};
                use crate::helpers::mont_reduce;
                use crate::helpers::full_reduce32;
                use crate::ntt::inv_ntt;
                use crate::D;

                // TODO: refactor
                let PublicKey {rho, cap_a_hat, tr, t1_d2_hat_mont} = &self;
                let (_, _, _, _) = (rho, cap_a_hat, tr, t1_d2_hat_mont);
                let t1_d2: [R; K] = inv_ntt(&core::array::from_fn(|k| T(core::array::from_fn(|n| full_reduce32(mont_reduce(t1_d2_hat_mont[k].0[n] as i64))))));
                let t1: [R; K] = core::array::from_fn(|k| R(core::array::from_fn(|n| t1_d2[k].0[n] >> D)));
                let pk = crate::encodings::pk_encode(rho, &t1);
                pk
             }
        }


        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::types::Ph;
            use rand_chacha::rand_core::SeedableRng;

            #[test]
            fn smoke_test() {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
                let message1 = [0u8, 1, 2, 3, 4, 5, 6, 7];
                let message2 = [7u8, 7, 7, 7, 7, 7, 7, 7];

                for _i in 0..32 {
                    let (pk, sk) = try_keygen_with_rng(&mut rng).unwrap();
                    let sig = sk.try_sign_with_rng(&mut rng, &message1, &[]).unwrap();
                    assert!(pk.verify(&message1, &sig, &[]));
                    assert!(!pk.verify(&message2, &sig, &[]));
                    for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
                        let sig = sk.try_hash_sign_with_rng(&mut rng, &message1, &[], &ph).unwrap();
                        let v = pk.hash_verify(&message1, &sig, &[], &ph);
                        assert!(v);
                    }
                    assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());
                }
            }
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
            let sig = ml_dsa::sign::<true, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, &sk, message, &[1], &[2], &[3], true
            )?;
            Ok(sig)
        }

        #[deprecated = "Temporary function to allow application of internal nist vectors; will be removed"]
        /// As of Oct 14 2024, the NIST test vectors are applied to the **internal** functions rather than
        /// the external API.
        ///
        /// The primary difference pertains to the prepending of domain, context, OID and
        /// hash information to the message in the `sign_finish()` and `verify_finish()` functions (follow
        /// the last `nist=true` function argument). This is expected to change such that the full API can
        /// be robustly tested - when this happens, this function will no longer be needed.
        /// # Errors
        /// Propagate errors from the `sign_finish()` function (for failing RNG).
        pub fn _internal_sign(
            sk: &PrivateKey, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8],
        ) -> Result<[u8; SIG_LEN], &'static str> {
            ensure!(ctx.len() < 256, "ML-DSA.Sign: ctx too long");
            let sig = ml_dsa::sign::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                rng, BETA, GAMMA1, GAMMA2, OMEGA, TAU, sk, message, ctx, &[], &[], true
            )?;
            Ok(sig)
        }

        #[deprecated = "Temporary function to allow application of internal nist vectors; will be removed"]
        #[must_use]
        /// As of Oct 14 2024, the NIST test vectors are applied to the **internal** functions rather than
        /// the external API.
        ///
        /// The primary difference pertains to the prepending of domain, context, OID and
        /// hash information to the message in the `sign_finish()` and `verify_finish()` functions (follow
        /// the last `nist=true` function argument). This is expected to change such that the full API can
        /// be robustly tested - when this happens, this function will no longer be needed.
        pub fn _internal_verify(pk: &PublicKey, message: &[u8], sig: &[u8; SIG_LEN], ctx: &[u8]) -> bool {
            if ctx.len() > 255 {
                return false;
            };
            let Ok(res) = ml_dsa::verify::<K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN, W1_LEN>(
                BETA, GAMMA1, GAMMA2, OMEGA, TAU, pk, &message, &sig, ctx, &[], &[], true
            ) else {
                return false;
            };
            res
        }
    };
}


/// Functionality for the **ML-DSA-44** security parameter set.
///
/// This includes specific sizes for the
/// public key, secret key, and signature along with a number of internal constants. The ML-DSA-44
/// parameter set is claimed to be in security strength category 2.
///
/// **1)** The basic usage is for an originator to start with the [`ml_dsa_44::try_keygen`] function below to
/// generate both [`ml_dsa_44::PublicKey`] and [`ml_dsa_44::PrivateKey`] structs. The resulting
/// [`ml_dsa_44::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies a variety of
/// functions to sign byte-array messages, such as [`traits::Signer::try_sign()`].
///
/// **2)** Both of the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait.
/// The originator utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the structs
/// into byte-arrays for storage and/or transmission, similar to the message. Upon retrieval and/or receipt,
/// the remote party utilizes the [`traits::SerDes::try_from_bytes()`] functions to deserialize the
/// byte-arrays into structs.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::verify()`] function implemented on the
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


/// Functionality for the **ML-DSA-65** security parameter set.
///
/// This includes specific sizes for the
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
/// **3)** Finally, the remote party uses the [`traits::Verifier::verify()`] function implemented on the
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


/// Functionality for the **ML-DSA-87** security parameter set.
///
/// This includes specific sizes for the
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
/// **3)** Finally, the remote party uses the [`traits::Verifier::verify()`] function implemented on the
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

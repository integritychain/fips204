use zeroize::{Zeroize, ZeroizeOnDrop};


/// Supported hash functions for `hash_sign()` and `hash_verify()` functions
pub enum Ph {
    /// Use SHA256 as the pre-hash function
    SHA256,
    /// Use SHA512 as the pre-hash function
    SHA512,
    /// Use Shake128 as the pre-hash function
    SHAKE128,
}


/// Correctly sized private key specific to the target security parameter set. <br>
/// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] trait.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PrivateKey<const SK_LEN: usize>(pub(crate) [u8; SK_LEN]);


/// Expanded private key, specific to the target security parameter set, that contains <br>
/// precomputed elements which increase (repeated) signature performance. Implements only
/// the [`crate::traits::Signer`] trait.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct ExpandedPrivateKey<const K: usize, const L: usize> {
    pub(crate) cap_k: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s_hat_1_mont: [T; L],
    pub(crate) s_hat_2_mont: [T; K],
    pub(crate) t_hat_0_mont: [T; K],
    pub(crate) cap_a_hat: [[T; L]; K],
}


/// Correctly sized public key specific to the target security parameter set. <br>
/// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PublicKey<const PK_LEN: usize>(pub(crate) [u8; PK_LEN]);


/// Expanded public key, specific to the target security parameter set, that contains <br>
/// precomputed elements which increase (repeated) verification performance. Implements only
/// the [`crate::traits::Verifier`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct ExpandedPublicKey<const K: usize, const L: usize> {
    pub(crate) cap_a_hat: [[T; L]; K],
    pub(crate) tr: [u8; 64],
    pub(crate) t1_d2_hat_mont: [T; K],
}


/// Polynomial coefficients in R, with default R0
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct R(pub(crate) [i32; 256]);
pub(crate) const R0: R = R([0i32; 256]);


/// Polynomial coefficients in T, with default T0
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct T(pub(crate) [i32; 256]);
pub(crate) const T0: T = T([0i32; 256]);


/// Individual Zq element
pub(crate) type Zq = i32;

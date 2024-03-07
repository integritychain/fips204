use zeroize::{Zeroize, ZeroizeOnDrop};


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
    pub(crate) s_hat_1: [T; L],
    pub(crate) s_hat_2: [T; K],
    pub(crate) t_hat_0: [T; K],
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
    pub(crate) t1_d2_hat: [T; K],
}


// Note: The following internal types may be reworked, perhaps as struct shells

pub(crate) trait Zero {
    fn zero() -> Self;
}

pub(crate) type Rq = i32;
pub(crate) type R = [Rq; 256];

impl Zero for R {
    fn zero() -> Self { [0i32; 256] }
}


pub(crate) type Tq = i32;
pub(crate) type T = [Tq; 256];


pub(crate) type Zq = i32;

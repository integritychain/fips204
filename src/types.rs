use zeroize::{Zeroize, ZeroizeOnDrop};


/// Correctly sized private key specific to the target security parameter set. <br>
/// Implements the [`crate::traits::Signer`], [`crate::traits::SerDes`], and
/// [`crate::traits::PreGen`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey<const SK_LEN: usize>(pub(crate) [u8; SK_LEN]);


/// Correctly sized public key specific to the target security parameter set. <br>
/// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PublicKey<const PK_LEN: usize>(pub(crate) [u8; PK_LEN]);


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

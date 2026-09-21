use zeroize::{Zeroize, ZeroizeOnDrop};


/// DER-encoded OIDs for commonly used digest functions for the pre-hash variant of ML-DSA.
/// See RFC 6234 (for SHA2), RFC 9688 (for SHA3), and RFC 8702 (for SHAKE).
/// These are all within the OID space prefixed by 2.16.840.1.101.3.4.2, a.k.a.
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)
/// See also https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
pub mod pre_hash {
    #![allow(dead_code)]

    /// DER-encoded OID for id-sha224
    pub const SHA2_224: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 ];
    /// DER-encoded OID for id-sha256
    pub const SHA2_256: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 ];
    /// DER-encoded OID for id-sha384
    pub const SHA2_384: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 ];
    /// DER-encoded OID for id-sha512
    pub const SHA2_512: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 ];
    /// DER-encoded OID for id-sha512-224
    pub const SHA2_512_224: [u8; 11] = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05 ];
    /// DER-encoded OID for id-sha512-256
    pub const SHA2_512_256: [u8; 11] = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06 ];
    /// DER-encoded OID for id-sha3-224
    pub const SHA3_224: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 ];
    /// DER-encoded OID for id-sha3-256
    pub const SHA3_256: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 ];
    /// DER-encoded OID for id-sha3-384
    pub const SHA3_384: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 ];
    /// DER-encoded OID for id-sha3-512
    pub const SHA3_512: [u8; 11]     = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A ];
    /// DER-encoded OID for id-shake128
    pub const SHAKE_128: [u8; 11]    = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B ];
    /// DER-encoded OID for id-shake256
    pub const SHAKE_256: [u8; 11]    = [ 0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C ];

}


/// Private key specific to the target security parameter set that contains
/// precomputed elements which improve signature performance.
///
/// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PrivateKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) cap_k: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s_1_hat_mont: [T; L],
    pub(crate) s_2_hat_mont: [T; K],
    pub(crate) t_0_hat_mont: [T; K],
}


/// Public key specific to the target security parameter set that contains
/// precomputed elements which improve verification performance.
///
/// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PublicKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) t1_d2_hat_mont: [T; K],
}


/// Polynomial coefficients in R, with default R0
#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
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

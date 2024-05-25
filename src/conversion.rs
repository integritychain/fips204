// This file implements functionality from FIPS 204 section 8.1 Conversion Between Data Types

use crate::helpers::{bit_length, ensure, is_in_range};
use crate::types::{R, R0};
use crate::Q;


// Algorithm 4: `IntegerToBits(x,alpha)` on page 20 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 5: `BitsToInteger(y)` on page 20 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 6: `BitsToBytes(y)` on page 21 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 7: `BytesToBits(z)` on page 21 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.


/// # Algorithm 8: `CoefFromThreeBytes(b0,b1,b2)` on page 21.
/// Generates an element of `{0, 1, 2, ... , q − 1} ∪ {⊥}` used in rejection sampling.
/// This function is used during keygen and signing, but only operates on the non-secret
/// `rho` value stored in the public key, so need not be constant-time in normal
/// operation. To support constant-time `dudect` measurements through the
/// `dudect_keygen_sign_with_rng()` function exposed when the `dudect` feature
/// is enabled, the CTEST value would be set to `true` to effectively bypass the rejection.
///
/// **Input**:  A byte array of length three, representing bytes `b0`, `b1`, `b2`.<br>
/// **Output**: An integer modulo `q` or `⊥` (returned as an Error).
///
/// # Errors
/// Returns an error `⊥` on input 3 bytes forming values between `Q=0x7F_E0_01`--`0x7F_FF_FF`,
/// and between `0xFF_E0_01`--`0xFF_FF_FF` (latter range due to masking of bit 7 of byte 2)
/// per spec; for rejection sampling.
pub(crate) fn coef_from_three_bytes<const CTEST: bool>(bbb: [u8; 3]) -> Result<i32, &'static str> {
    // 1: if b2 > 127 then
    // 2: b2 ← b2 − 128     ▷ Set the top bit of b2 to zero
    // 3: end if
    let bbb2 = i32::from(bbb[2] & 0x7F);
    let bbb2 = if CTEST { bbb2 & 0x3F } else { bbb2 }; // Used only for `dudect` measurements

    // 4: z ← 2^16·b_2 + 2^8·b1 + b0
    let z = (bbb2 << 16) | (i32::from(bbb[1]) << 8) | i32::from(bbb[0]);

    // 5: if z < q then return z
    if z < Q {
        Ok(z)

        // 6: else return ⊥
    } else {
        Err("Alg 8: returns ⊥")

        // 7: end if
    }
}


/// # Algorithm 9: `CoefFromHalfByte(b)` on page 22.
/// Generates an element of `{−η, −η + 1, ... , η} ∪ {⊥}` used in rejection sampling.
/// This function is used during keygen, but only operates on the hash-derived
/// `rho_prime` value that is rejection-sampled/expanded into the internal `s_1` and
/// `s_2`, so need not be constant-time in normal operation. To support constant-time
/// `dudect` measurements through the `dudect_keygen_sign_with_rng()` function exposed
/// when the `dudect` feature is enabled, the CTEST value would be set to `true` to
/// effectively bypass the rejection.
///
/// **Input**:  Integer `b` ∈ {0, 1, ... , 15}.
///             Security parameter `η` (eta) must be either 2 or 4.<br>
/// **Output**: An integer between `−η` and `η`, or `⊥`.
///
/// # Errors
/// Returns an error `⊥` on when eta = 4 and b > 8 for rejection sampling. (panics on b > 15)
#[allow(clippy::cast_possible_truncation)] // rem as u8
pub(crate) fn coef_from_half_byte<const CTEST: bool>(eta: i32, b: u8) -> Result<i32, &'static str> {
    const M5: u32 = ((1u32 << 24) / 5) + 1;
    debug_assert!((eta == 2) | (eta == 4), "Alg 9: incorrect eta");
    debug_assert!(b < 16, "Alg 9: b out of range"); // Note other cases involving b/eta will fall through to Err()

    let b = if CTEST { b & 0x07 } else { b };
    // 1: if η = 2 and b < 15 then return 2 − (b mod 5)
    if (eta == 2) & (b < 15) {
        // note 15, not 16
        let quot = (u32::from(b) * M5) >> 24;
        let rem = u32::from(b) - quot * 5;
        Ok(2 - i32::from(rem as u8))

        // 2: else
    } else {
        //
        // 3: if η = 4 and b < 9 then return 4 − b
        if (eta == 4) & (b < 9) {
            Ok(4 - i32::from(b))

            // 4: else return ⊥
        } else {
            Err("Alg 9: returns ⊥") // not necessarily an error per se, but rather "try again" (we can have eta==2 & b == 15)

            // 5: end if
        }

        // 6: end if
    }
}


/// # Algorithm 10: `SimpleBitPack(w,b)` on page 22.
/// Encodes a polynomial `w` into a byte string. This function is not exposed to unvalidated input.
///
/// **Input**:  `b ∈ N` and `w ∈ R` such that the coefficients of `w` are all in `[0, b]`.
///             Security parameter `b` must be positive and have a bit length of less than 20.<br>
/// **Output**: A byte string of length `32·bitlen(b)`.
pub(crate) fn simple_bit_pack(w: &R, b: i32, bytes_out: &mut [u8]) {
    debug_assert!((1..1024 * 1024).contains(&b), "Alg 10: b out of range"); // plenty of headroom
    debug_assert!(is_in_range(w, 0, b), "Alg 10: w out of range"); // early detect; repeated within bit_pack
    debug_assert_eq!(bytes_out.len(), 32 * bit_length(b), "Alg 10: incorrect size of output bytes");

    bit_pack(w, 0, b, bytes_out);
}


/// # Algorithm 11: `BitPack(w,a,b)` on page 22.
/// Encodes a polynomial `w` into a byte string.  This function is not exposed to unvalidated input.
///
/// **Input**:  `a, b ∈ N` and `w ∈ R` such that the coefficients of `w` are all in `[−a, b]`.
///             Security parameter `a` must be non-negative and have a bit length of less than 20.
///             Security parameter `b` must be positive and have a bit length of less than 20.<br>
/// **Output**: A byte string of length `32·bitlen(a + b)`.
pub(crate) fn bit_pack(w: &R, a: i32, b: i32, bytes_out: &mut [u8]) {
    debug_assert!((0..1024 * 1024).contains(&a), "Alg 11: a out of range");
    debug_assert!((1..1024 * 1024).contains(&b), "Alg 11: b out of range");
    debug_assert!(is_in_range(w, a, b), "Alg 11: w out of range");
    debug_assert_eq!(w.0.len() * bit_length(a + b), bytes_out.len() * 8, "Alg 11: bad output size");

    let bitlen = bit_length(a + b); // Calculate each element bit length
    let mut temp = 0u32; // To insert new values on the left/MSB and pop output values from the right/LSB
    let mut byte_index = 0; // Current output byte position
    let mut bit_index = 0; // Number of bits accumulated in temp

    // For every coefficient in w... (which is known to be in suitably positive range)
    #[allow(clippy::cast_sign_loss)]
    for coeff in w.0 {
        // if we have a negative `a` bound, subtract from b and shift into empty/upper part of temp
        if a > 0 {
            temp |= ((b - coeff) as u32) << bit_index;
        // Otherwise, we just shift and drop into empty/upper part of temp
        } else {
            temp |= (coeff as u32) << bit_index;
        }
        // account for the amount of bits we now have in temp
        bit_index += bitlen;
        // while we have at least 'bytes' worth of bits in temp
        while bit_index > 7 {
            // drop a byte into the output
            bytes_out[byte_index] = temp.to_le_bytes()[0];
            temp >>= 8;
            // update indexes
            byte_index += 1;
            bit_index -= 8;
        }
    }
}


/// # Algorithm 12: `SimpleBitUnpack(v,b)` on page 23.
/// Reverses the procedure `SimpleBitPack`. Used in Algorithm 17's `pkDecode()` function which
/// does take untrusted input via deserialization (and `verify_start()`).
///
/// **Input**:  `b ∈ N` and a byte string `v` of length 32·bitlen(b).
///             Security parameter `b` must be positive and have a bit length of less than 20.<br>
/// **Output**: A polynomial `w ∈ R`, with coefficients in `[0, 2^c−1]`, where `c = bitlen(b)`.
///             When `b + 1` is a power of 2, the coefficients are in `[0, b]`.
///
/// # Errors
/// Returns an error on `w` out of range.
pub(crate) fn simple_bit_unpack(v: &[u8], b: i32) -> Result<R, &'static str> {
    debug_assert!((1..1024 * 1024).contains(&b), "Alg 12: b out of range");
    debug_assert_eq!(v.len(), 32 * bit_length(b), "Alg 12: bad output size");

    // Note that `w_out` is correctly range checked (via ensure!) in `bit_unpack()`
    let w_out = bit_unpack(v, 0, b).map_err(|_| "Alg 12: w out of range")?;
    Ok(w_out)
}


/// # Algorithm 13: `BitUnpack(v,a,b)` on page 23.
/// Reverses the procedure `BitPack`. Used in Algorithm 12 above, as well as
/// Algorithm 19's `skDecode()` function, Algorithm 21's `sigDecode()` function,
/// and Algorithm 28's `expand_mask()` function. The latter function is used in
///`ml_dsa::sign_finish()`. The first three (12/19/21) take untrusted input.
///
/// **Input**:  `a, b ∈ N` and a byte string `v` of length `32·bitlen(a + b)`.
///             Security parameter `a` must be non-negative and have a bit length of less than 20.
///             Security parameter `b` must be positive and have a bit length of less than 20.<br>
/// **Output**: A polynomial `w ∈ R`, with coefficients in `[b − 2^c + 1, b]`, where `c = bitlen(a + b)`. <br>
///             When `a + b + 1` is a power of 2, the coefficients are in `[−a, b]`.
///
/// # Errors
/// Returns an error on `w` out of range.
pub(crate) fn bit_unpack(v: &[u8], a: i32, b: i32) -> Result<R, &'static str> {
    debug_assert!((0..1024 * 1024).contains(&a), "Alg 13: a out of range");
    debug_assert!((1..1024 * 1024).contains(&b), "Alg 13: b out of range");
    debug_assert_eq!(v.len(), 32 * bit_length(a + b), "Alg 13: bad output size");

    let bitlen = bit_length(a + b).try_into().expect("Alg 13: try_into fail");
    let mut w_out = R([0i32; 256]);
    let mut temp = 0i32;
    let mut r_index = 0;
    let mut bit_index = 0;

    for byte in v {
        temp |= i32::from(*byte) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            let tmask = temp & ((1 << bitlen) - 1);
            // choice fixed by security parameter, so CT
            w_out.0[r_index] = if a == 0 { tmask } else { b - tmask };
            bit_index -= bitlen;
            temp >>= bitlen;
            r_index += 1;
        }
    }

    let bot = i32::abs(b - (1 << bitlen) + 1); // b − 2^c + 1 (as abs)
    ensure!(is_in_range(&w_out, bot, b), "Alg 13: w out of range");
    Ok(w_out)
}


/// # Algorithm 14: `HintBitPack(h)` on page 24.
/// Encodes a polynomial vector `h` with binary coefficients into a byte string.
/// This function is used during signing, but only to produce the non-secret output
/// signature, so need not be constant-time in normal operation. To support
/// constant-time `dudect` measurements through the `dudect_keygen_sign_with_rng()`
/// function exposed when the `dudect` feature is enabled, the CTEST value would be
/// set to `true` to effectively bypass some of the loop decisions.
///
/// **Input**:  A polynomial vector `h ∈ R^k_2` such that at most `ω` of the coefficients in `h` are equal to `1`.
///             Security parameters `ω` (omega) and k must sum to be less than 256. <br>
/// **Output**: A byte string `y` of length `ω + k`.
pub(crate) fn hint_bit_pack<const CTEST: bool, const K: usize>(
    omega: i32, h: &[R; K], y_bytes: &mut [u8],
) {
    let omega_u = usize::try_from(omega).expect("cannot fail");
    debug_assert!((1..255).contains(&(omega_u + K)), "Alg 14: omega+K out of range");
    debug_assert_eq!(y_bytes.len(), omega_u + K, "Alg 14: bad output size");
    debug_assert!(h.iter().all(|r| is_in_range(r, 0, 1)), "Alg 14: h not 0/1");
    debug_assert!(
        h.iter().all(|r| r.0.iter().filter(|&e| *e == 1).sum::<i32>() <= omega),
        "Alg 14: too many 1's in h"
    );

    // 1: y ∈ B^{ω+k} ← 0^{ω+k}
    y_bytes.iter_mut().for_each(|e| *e = 0);

    // 2: Index ← 0
    let mut index = 0;

    // 3: for i from 0 to k − 1 do
    for i in 0..K {
        //
        // 4: for j from 0 to 255 do
        for j in 0..256 {
            //
            // 5: if h[i]_j != 0 then
            if CTEST & (index > (y_bytes.len() - 1)) {
                continue;
            };
            if CTEST | (h[i].0[j] != 0) {
                //
                // 6: y[Index] ← j      ▷ Store the locations of the nonzero coefficients in h[i]
                y_bytes[index] = j.to_le_bytes()[0];
                //
                // 7: Index ← Index + 1
                index += 1;

                // 8: end if
            }

            // 9: end for
        }

        // 10: y[ω + i] ← Index ▷ Store the value of Index after processing h[i]
        y_bytes[omega_u + i] = index.to_le_bytes()[0];

        // 11: end for
    }

    // 12: return y
}


/// # Algorithm 15: `HintBitUnpack(y)` on page 24.
/// Reverses the procedure `HintBitPack`.
///
/// **Input**:  A byte string `y` of length `ω + k`.
///             Security parameters `ω` (omega) and k must sum to be less than 256. <br>
/// **Output**: A polynomial vector `h ∈ R^k_2` or `⊥` (as an Error).
///
/// # Errors
/// Returns an error on invalid input.
pub(crate) fn hint_bit_unpack<const K: usize>(
    omega: i32, y_bytes: &[u8],
) -> Result<[R; K], &'static str> {
    let omega_u = usize::try_from(omega).expect("Alg 15: omega try_into fail");
    debug_assert!((K + 1..255).contains(&(omega_u + K)), "Alg 15: omega+K too large");
    debug_assert_eq!(y_bytes.len(), omega_u + K, "Alg 15: bad output size");

    // 1: h ∈ R^k_2 ∈ ← 0^k
    let mut h: [R; K] = [R0; K];

    // 2: Index ← 0
    let mut index = 0;

    // 3: for i from 0 to k − 1 do
    for i in 0..K {
        //
        // 4: if y[ω + i] < Index or y[ω + i] > ω then return ⊥
        if (y_bytes[omega_u + i] < index) | (y_bytes[omega_u + i] > omega.to_le_bytes()[0]) {
            return Err("Alg 15a: returns ⊥");

            // 5: end if
        }

        // Note that there is a bug in the FIPS 204 draft specification that allows forgeability.
        // Discussion/thread here: https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/TQo-qFbBO1A/m/YcYKjMblAAAJ
        // The missed portion of reference code: https://github.com/pq-crystals/dilithium/blob/master/ref/packing.c#L223
        // The code currently implemented here intentionally matches the flawed FIPS 204 draft spec.
        // The `bad_sig()` test implemented in `integration.rs` demonstrates the flaw, and the adjacent `forever()`
        // test is able to uncover additional instances.
        // This code will implement the fix forthcoming in FIPS 204 as soon as it is available.

        // 6: while Index < y[ω + i] do
        while index < y_bytes[omega_u + i] {
            //
            // 7: h[i]_{y[Index]} ← 1
            h[i].0[y_bytes[index as usize] as usize] = 1;

            // 8: Index ← Index + 1
            index += 1;

            // 9: end while
        }

        // 10: end for
    }

    // 11: while Index < ω do
    while index < omega.to_le_bytes()[0] {
        //
        // 12: if y[Index] != 0 then return ⊥
        if y_bytes[index as usize] != 0 {
            return Err("Alg 15b: returns ⊥");

            // 13: end if
        }

        // 14: Index ← Index + 1
        index += 1;

        // 15: end while
    }

    // 16: return h
    debug_assert!(
        h.iter().all(|r| r.0.iter().filter(|&&e| e == 1).sum::<i32>() <= omega),
        "Alg 15: too many 1's in h"
    );
    Ok(h)
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn test_coef_from_three_bytes1() {
        let bytes = [0x12u8, 0x34, 0x56];
        let res = coef_from_three_bytes::<false>(bytes).unwrap();
        assert_eq!(res, 0x0056_3412);
    }

    #[test]
    fn test_coef_from_three_bytes2() {
        let bytes = [0x12u8, 0x34, 0x80];
        let res = coef_from_three_bytes::<false>(bytes).unwrap();
        assert_eq!(res, 0x0000_3412);
    }

    #[test]
    fn test_coef_from_three_bytes3() {
        let bytes = [0x01u8, 0xe0, 0x80];
        let res = coef_from_three_bytes::<false>(bytes).unwrap();
        assert_eq!(res, 0x0000_e001);
    }

    #[test]
    #[should_panic(expected = "panic: out of range")]
    fn test_coef_from_three_bytes4() {
        let bytes = [0x01u8, 0xe0, 0x7f];
        let res = coef_from_three_bytes::<false>(bytes).expect("panic: out of range");
        assert_eq!(res, 0x0056_3412);
    }

    #[test]
    fn test_coef_from_half_byte1() {
        let inp = 3;
        let res = coef_from_half_byte::<false>(2, inp).unwrap();
        assert_eq!(-1, res);
    }

    #[test]
    fn test_coef_from_half_byte2() {
        let inp = 8;
        let res = coef_from_half_byte::<false>(4, inp).unwrap();
        assert_eq!(-4, res);
    }

    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    #[test]
    fn test_coef_from_half_byte_validation1() {
        let inp = 22;
        let res = coef_from_half_byte::<false>(2, inp);
        assert!(res.is_err());
    }

    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    #[test]
    fn test_coef_from_half_byte_validation2() {
        let inp = 5;
        let res = coef_from_half_byte::<false>(1, inp);
        assert!(res.is_err());
    }

    #[test]
    fn test_coef_from_half_byte_validation3() {
        let inp = 10;
        let res = coef_from_half_byte::<false>(4, inp);
        assert!(res.is_err());
    }

    #[test]
    fn test_simple_bit_pack_roundtrip() {
        // Round trip for 32 * 6(bitlen) bytes
        let mut random_bytes = [0u8; 32 * 6];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let r = simple_bit_unpack(&random_bytes, (1 << 6) - 1).unwrap();
        let mut res = [0u8; 32 * 6];
        simple_bit_pack(&r, (1 << 6) - 1, &mut res);
        assert_eq!(random_bytes, res);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    fn test_simple_bit_unpack_validation1() {
        // wrong size of bytes
        let mut random_bytes = [0u8; 32 * 7];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let res = simple_bit_unpack(&random_bytes, (1 << 6) - 1);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    fn test_bit_unpack_validation1() {
        // wrong size of bytes
        let mut random_bytes = [0u8; 32 * 7];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let res = bit_unpack(&random_bytes, 0, (1 << 6) - 1);
        assert!(res.is_err());
    }

    #[test]
    fn test_simple_bit_pack_validation1() {
        let mut random_bytes = [0u8; 32 * 6];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let r = R([0i32; 256]);
        simple_bit_pack(&r, (1 << 6) - 1, &mut random_bytes);
        // no panic is good news
    }
}

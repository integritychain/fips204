//! This file implements functionality from FIPS 204 section 8.1 Conversion Between Data Types

use crate::helpers::{bit_length, ensure, is_in_range};
use crate::types::{Zero, R};
use crate::Q;


// Algorithm 4: `IntegerToBits(x, alpha)` on page 20 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 5: `BitsToInteger(y)` on page 20 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 6: `BitsToBytes(y)` on page 21 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.

// Algorithm 7: `BytesToBits(z)` on page 21 is not needed because the pack and unpack
// algorithms have been reimplemented at a higher level.


/// # Algorithm 8: `CoefFromThreeBytes(b0,b1,b2)` on page 21.
/// Generates an element of `{0, 1, 2, ... , q − 1} ∪ {⊥}`.
///
/// **Input**: A byte array of length three, representing bytes `b0`, `b1`, `b2`. <br>
/// **Output**: An integer modulo `q` or `⊥` (returned as an Error).
///
/// # Errors
/// Returns an error `⊥` on input between `Q` and `0x7F_FF_FF` (per spec; for rejection sampling).
pub(crate) fn coef_from_three_bytes(bbb: [u8; 3]) -> Result<i32, &'static str> {
    // 1: if b2 > 127 then
    // 2: b2 ← b2 − 128     ▷ Set the top bit of b2 to zero
    // 3: end if
    let bbb2 = i32::from(bbb[2] & 0x7F);

    // 4: z ← 2^16·b_2 + 2^8·b1 + b0
    let z = 2i32.pow(16) * bbb2 + 2i32.pow(8) * i32::from(bbb[1]) + i32::from(bbb[0]);

    // 5: if z < q then return z
    if z < Q {
        Ok(z)

        // 6: else return ⊥
    } else {
        Err("Alg8: returns ⊥")

        // 7: end if
    }
}


/// # Algorithm 9: `CoefFromHalfByte(b)` on page 22.
/// Generates an element of `{−η, −η + 1, ... , η} ∪ {⊥}`.
/// Not intended to be constant time.
///
/// **Input**: Integer `b` ∈ {0, 1, ... , 15}. <br>
/// **Output**: An integer between `−η` and `η`, or `⊥`. <br>
/// Security parameter ETA is `η`
///
/// # Panics
/// In debug, requires `eta > 0`.
///
/// # Errors
/// Returns an error `⊥` on misconfigured or illegal input (`b` > 15).
pub(crate) fn coef_from_half_byte_vt(eta: i32, b: u8) -> Result<i32, &'static str> {
    debug_assert!(eta > 0);
    ensure!(b <= 15, "Alg9: b > 15");

    // 1: if η = 2 and b < 15 then return 2 − (b mod 5)
    if (eta == 2) & (b < 15) {
        Ok(2 - (i32::from(b) % 5))

        // 2: else
    } else {
        //
        // 3: if η = 4 and b < 9 then return 4 − b
        if (eta == 4) & (b < 9) {
            Ok(4 - i32::from(b))

            // 4: else return ⊥
        } else {
            Err("Alg9: returns `⊥`")

            // 5: end if
        }
        // 6: end if
    }
}


/// # Algorithm 10: `SimpleBitPack(w,b)` on page 22.
/// Encodes a polynomial `w` into a byte string.
///
/// **Input**: `b ∈ N` and `w ∈ R` such that the coefficients of `w` are all in `[0, b]`. <br>
/// **Output**: A byte string of length `32·bitlen(b)`.
///
/// # Panics
/// In debug, requires `b > 0` and `b <= i32::MAX / 32`.
///
/// # Errors
/// Returns an error on any out-of-range coefficients of `w`.
pub(crate) fn simple_bit_pack(w: &R, b: i32, bytes_out: &mut [u8]) -> Result<(), &'static str> {
    debug_assert!((1..i32::MAX / 32).contains(&b), "Alg10: b out of range");
    debug_assert_eq!(bytes_out.len(), 32 * bit_length(b), "Alg10: incorrect size of output bytes");

    ensure!(is_in_range(w, 0, b), "Alg10: w out of range");
    bit_pack(w, 0, b, bytes_out)?;
    Ok(())
}


/// # Algorithm 11: `BitPack(w,a,b)` on page 22
/// Encodes a polynomial `w` into a byte string.
///
/// **Input**: `a, b ∈ N` and `w ∈ R` such that the coefficients of `w` are all in `[−a, b]`. <br>
/// **Output**: A byte string of length `32·bitlen(a + b)`.
///
/// # Panics
/// In debug, requires `a >= 0` and `a <= i32::MAX / 64`.
/// In debug, requires `b > 0` and `b <= i32::MAX / 64`.
///
/// # Errors
/// Returns an error on any out-of-range coefficients of `w`.
pub(crate) fn bit_pack(w: &R, a: i32, b: i32, bytes_out: &mut [u8]) -> Result<(), &'static str> {
    debug_assert!((0..i32::MAX / 64).contains(&a), "Alg11: a out of range");
    debug_assert!((1..i32::MAX / 64).contains(&b), "Alg11: b out of range");
    debug_assert_eq!(
        w.len() * bit_length(a + b),
        bytes_out.len() * 8,
        "Alg11: incorrect size of output bytes"
    );

    ensure!(is_in_range(w, a, b), "Alg11: w out of range");
    let bitlen = bit_length(a + b); // Calculate element bit length
    let mut temp = 0u64; // Insert new values on the left/MSB and pop output values from the right/LSB
    let mut byte_index = 0; // Current output byte position
    let mut bit_index = 0; // Number of bits accumulated in temp

    // For every coefficient in w... (which is ensured to be in range)
    #[allow(clippy::cast_sign_loss)]
    for coeff in *w {
        // if we have a negative `a` bound, subtract from b and shift into empty/upper part of temp
        if a > 0 {
            temp |= ((b - coeff) as u64) << bit_index;
        // Otherwise, we just shift and drop into empty/upper part of temp
        } else {
            temp |= (coeff as u64) << bit_index;
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
    Ok(())
}


/// # Algorithm 12: `SimpleBitUnpack(v,b)` on page 23.
/// Reverses the procedure `SimpleBitPack`.
///
/// **Input**: `b ∈ N` and a byte string `v` of length 32·bitlen(b). <br>
/// **Output**: A polynomial `w ∈ R`, with coefficients in `[0, 2^c−1]`, where `c = bitlen(b)`. <br>
/// When `b + 1` is a power of 2, the coefficients are in `[0, b]`.
///
/// # Panics
/// In debug, requires `b > 0` and `b <= i32::MAX / 32`.
///
/// # Errors
/// Returns an error on `w` out of range and incorrectly sized `v`.
pub(crate) fn simple_bit_unpack(v: &[u8], b: i32) -> Result<R, &'static str> {
    debug_assert!((1..i32::MAX / 32).contains(&b), "Alg12: b out of range");
    debug_assert_eq!(v.len(), 32 * bit_length(b), "Alg12: incorrectly sized v");

    let w_out = bit_unpack(v, 0, b)?;
    ensure!(is_in_range(&w_out, 0, b), "Alg12: w out of range");
    Ok(w_out)
}


/// # Algorithm 13: `BitUnpack(v,a,b)` on page 23.
/// Reverses the procedure `BitPack`.
///
/// **Input**: `a, b ∈ N` and a byte string `v` of length `32·bitlen(a + b)`. <br>
/// **Output**: A polynomial `w ∈ R`, with coefficients in `[b − 2c + 1, b]`, where `c = bitlen(a + b)`. <br>
/// When `a + b + 1` is a power of 2, the coefficients are in `[−a, b]`.
///
/// # Panics
/// In debug, requires `a >= 0` and `a <= i32::MAX / 64`.
/// In debug, requires `b > 0` and `b < i32::MAX / 64`.
///
/// # Errors
/// Returns an error on `w` out of range, or an incorrectly sized `v`.
pub(crate) fn bit_unpack(v: &[u8], a: i32, b: i32) -> Result<R, &'static str> {
    debug_assert!((0..i32::MAX / 64).contains(&a), "Alg13: a out of range");
    debug_assert!((1..i32::MAX / 64).contains(&b), "Alg13: b out of range");
    debug_assert_eq!(v.len(), 32 * bit_length(a + b), "Alg13: incorrectly sized v");

    let bitlen = bit_length(a + b).try_into().expect("Alg13: try_into fail");
    let mut w_out = [0i32; 256];
    let mut temp = 0i32;
    let mut r_index = 0;
    let mut bit_index = 0;

    for byte in v {
        temp |= i32::from(*byte) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            let tmask = temp & (2i32.pow(bitlen) - 1);
            // choice fixed by security parameter, so CT
            w_out[r_index] = if a == 0 { tmask } else { b - tmask };
            bit_index -= bitlen;
            temp >>= bitlen;
            r_index += 1;
        }
    }
    ensure!(is_in_range(&w_out, a, b), "Alg13: w out of range");
    Ok(w_out)
}


/// # Algorithm 14: `HintBitPack(h)` on page 24.
/// Encodes a polynomial vector `h` with binary coefficients into a byte string.
///
/// **Input**: A polynomial vector `h ∈ R^k_2` such that at most `ω` of the coefficients in `h` are equal to `1`. <br>
/// **Output**: A byte string `y` of length `ω + k`.
///
/// # Panics
/// In debug, requires `y` of length `ω + k`.
/// In debug, requires 1 < `ω + k` < 255
///
/// # Errors
/// Returns an error on too many `1` in `h`, or values other than `0` & `1` in h
pub(crate) fn hint_bit_pack<const K: usize>(
    omega: i32, h: &[R; K], y_bytes: &mut [u8],
) -> Result<(), &'static str> {
    let omega_u = usize::try_from(omega).expect("Alg14: omega try_into fail");
    debug_assert!((1..255).contains(&(omega_u + K)), "Alg14: omega out of range");
    debug_assert_eq!(y_bytes.len(), omega_u + K, "Alg14: incorrectly sized output bytes");

    // TODO: reconsider whether these should be debug_assert! or ensure!
    ensure!(h.iter().all(|r| is_in_range(r, 0, 1)), "Alg14: h not 0/1");
    ensure!(
        h.iter().all(|&r| r.iter().filter(|&e| *e == 1).sum::<i32>() <= omega),
        "Alg14: too many 1's in h"
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
            if h[i][j] != 0 {
                //
                // 6: y[Index] ← j      ▷ Store the locations of the nonzero coefficients in h[i]
                y_bytes[index] = j.to_le_bytes()[0];
                //
                // 7: Index ← Index + 1
                index += 1;

                // slightly redundant, per count in second ensure above
                ensure!(index < y_bytes.len(), "Alg14: index has gone out of range");
                // 8: end if
            }

            // 9: end for
        }

        // 10: y[ω + i] ← Index ▷ Store the value of Index after processing h[i]
        y_bytes[omega_u + i] = u8::try_from(index).map_err(|_| "Alg14: index > u8::MAX")?;

        // 11: end for
    }

    // 12: return y
    Ok(())
}


/// # Algorithm 15: `HintBitUnpack(y)` on page 24.
/// Reverses the procedure `HintBitPack`.
///
/// **Input**: A byte string `y` of length `ω + k`. <br>
/// **Output**: A polynomial vector `h ∈ R^k_2` or `⊥` (as an Error).
///
/// # Panics
/// In debug, requires `y` of length `ω + k`.
/// In debug, requires 1 < `ω + k` < 255
///
/// # Errors
/// Returns an error on incorrectly sized or illegal inputs.
pub(crate) fn hint_bit_unpack<const K: usize>(
    omega: i32, y_bytes: &[u8],
) -> Result<[R; K], &'static str> {
    let omega_u = usize::try_from(omega).expect("Alg15: omega try_into fail");
    debug_assert_eq!(y_bytes.len(), omega_u + K);
    debug_assert!((0..255usize).contains(&(omega_u + K)), "Alg15: omega too large");

    // 1: h ∈ R^k_2 ∈ ← 0^k
    let mut h = [R::zero(); K];

    // 2: Index ← 0
    let mut index = 0;

    // 3: for i from 0 to k − 1 do
    for i in 0..K {
        //
        // 4: if y[ω + i] < Index or y[ω + i] > ω then return ⊥
        if (y_bytes[omega_u + i] < index) | (y_bytes[omega_u + i] > omega.to_le_bytes()[0]) {
            return Err("Alg15: returns ⊥ a");

            // 5: end if
        }

        // 6: while Index < y[ω + i] do
        while index < y_bytes[omega_u + i] {
            //
            // 7: h[i]_{y[Index]} ← 1
            h[i][y_bytes[index as usize] as usize] = 1;

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
            return Err("Alg15: returns ⊥ b");

            // 13: end if
        }

        // 14: Index ← Index + 1
        index += 1;

        // 15: end while
    }

    // 16: return h
    ensure!(
        h.iter().all(|&r| r.iter().filter(|&&e| e == 1).sum::<i32>() <= omega),
        "Alg15: too many 1's in h"
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
        let res = coef_from_three_bytes(bytes).unwrap();
        assert_eq!(res, 0x0056_3412);
    }

    #[test]
    fn test_coef_from_three_bytes2() {
        let bytes = [0x12u8, 0x34, 0x80];
        let res = coef_from_three_bytes(bytes).unwrap();
        assert_eq!(res, 0x0000_3412);
    }

    #[test]
    fn test_coef_from_three_bytes3() {
        let bytes = [0x01u8, 0xe0, 0x80];
        let res = coef_from_three_bytes(bytes).unwrap();
        assert_eq!(res, 0x0000_e001);
    }

    #[test]
    #[should_panic]
    fn test_coef_from_three_bytes4() {
        let bytes = [0x01u8, 0xe0, 0x7f];
        let res = coef_from_three_bytes(bytes).expect("panic: out of range");
        assert_eq!(res, 0x0056_3412);
    }

    #[test]
    fn test_coef_from_half_byte1() {
        let inp = 3;
        let res = coef_from_half_byte_vt(2, inp).unwrap();
        assert_eq!(-1, res);
    }

    #[test]
    fn test_coef_from_half_byte2() {
        let inp = 8;
        let res = coef_from_half_byte_vt(4, inp).unwrap();
        assert_eq!(-4, res);
    }

    #[test]
    fn test_coef_from_half_byte_validation1() {
        let inp = 22;
        let res = coef_from_half_byte_vt(2, inp);
        assert!(res.is_err());
    }

    #[test]
    fn test_coef_from_half_byte_validation2() {
        let inp = 15;
        let res = coef_from_half_byte_vt(2, inp);
        assert!(res.is_err());
    }

    #[test]
    fn test_coef_from_half_byte_validation3() {
        let inp = 10;
        let res = coef_from_half_byte_vt(4, inp);
        assert!(res.is_err());
    }

    #[test]
    fn test_simple_bit_pack_roundtrip() {
        // Round trip for 32 * 6(bitlen) bytes
        let mut random_bytes = [0u8; 32 * 6];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let r = simple_bit_unpack(&random_bytes, 2i32.pow(6) - 1).unwrap();
        let mut res = [0u8; 32 * 6];
        simple_bit_pack(&r, 2i32.pow(6) - 1, &mut res).unwrap();
        assert_eq!(random_bytes, res);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    fn test_simple_bit_unpack_validation1() {
        // wrong size of bytes
        let mut random_bytes = [0u8; 32 * 7];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let res = simple_bit_unpack(&random_bytes, 2i32.pow(6) - 1);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    fn test_bit_unpack_validation1() {
        // wrong size of bytes
        let mut random_bytes = [0u8; 32 * 7];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let res = bit_unpack(&random_bytes, 0, 2i32.pow(6) - 1);
        assert!(res.is_err());
    }

    #[test]
    fn test_simple_bit_pack_validation1() {
        let mut random_bytes = [0u8; 32 * 6];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let r = [0i32; 256];
        let res = simple_bit_pack(&r, 2i32.pow(6) - 1, &mut random_bytes);
        assert!(res.is_ok());
    }

    #[test]
    #[should_panic]
    #[allow(clippy::should_panic_without_expect)]
    fn test_simple_bit_pack_validation2() {
        let mut random_bytes = [0u8; 32 * 7];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        // wrong size r coeff
        let r = [1024i32; 256];
        let res = simple_bit_pack(&r, 2i32.pow(6) - 1, &mut random_bytes);
        assert!(res.is_err());
    }

    // TODO: reword to start with bit_pack..
    // #[test]
    // fn test_bit_pack_roundtrip() {
    //     // Round trip for 32 * 6(bitlen) bytes
    //     let random_bytes: Vec<u8> = (0..32 * 6).map(|_| rand::random::<u8>()).collect();
    //     let mut r = bit_unpack(&random_bytes, 2u32.pow(2), 2u32.pow(6) - 2u32.pow(2) - 1).unwrap();
    //     let mut res = [0u8; 32 * 6];
    //     bit_pack(&r, 2u32.pow(2), 2u32.pow(6) - 2u32.pow(2) - 1, &mut res);
    //     assert_eq!(random_bytes, res);
    // }

    // TODO test hint_bit_pack and hint_bit_unpack
}

//! This file implements functionality from FIPS 204 section 8.3 Hashing and Pseudorandom Sampling

use crate::conversion::{bit_unpack, coef_from_half_byte_vartime, coef_from_three_bytes_vartime};
use crate::helpers::{bit_length, is_in_range};
use crate::types::{R, R0, T, T0};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};


/// # Function H(v,d) of (8.1) on page 29.
/// Takes a reference to a list of byte-slice references and runs them through Shake256.
/// Returns a xof reader for extracting extendable output.
pub(crate) fn h_xof(v: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake256::default();
    v.iter().for_each(|b| hasher.update(b));
    hasher.finalize_xof()
}


/// # Function `H_128(v,d)` of (8.2) on page 29.
/// Takes a reference to a list of byte-slice references and runs them through Shake128.
/// Returns a xof reader for extracting extendable output.
pub(crate) fn h128_xof(v: &[&[u8]]) -> impl XofReader {
    let mut hasher = Shake128::default();
    v.iter().for_each(|b| hasher.update(b));
    hasher.finalize_xof()
}


/// # Algorithm 23: `SampleInBall(ρ)` on page 30.
/// Samples a polynomial `c ∈ Rq` with coefficients from `{−1, 0, 1}` and Hamming weight `τ`.
/// Used in `ml_dsa:sign_finish()` and `ml_dsa::verify_finish()`. TODO: review constant-time aspects
///
/// **Input**: A seed `ρ ∈{0,1}^256` <br>
/// **Output**: A polynomial `c` in `Rq`.
pub(crate) fn sample_in_ball<const CTEST: bool>(tau: i32, rho: &[u8; 32]) -> R {
    let tau = usize::try_from(tau).expect("cannot fail");
    let mut xof = h_xof(&[rho]);
    let mut hpk8 = [0u8; 8];
    xof.read(&mut hpk8); // Save the first 8 bytes for step 9

    // 1: c ← 0
    let mut c = R0;
    // 2: k ← 8; k implicitly advances with each sample
    let mut hpk = [0u8];

    // 3: for i from 256 − τ to 255 do
    for i in (256 - tau)..=255 {
        //
        // 4: while H(ρ)[[k]] > i do
        // 5: k ← k + 1
        // 6: end while
        // The above/below loop reads xof bytes until less than or equal to i
        loop {
            xof.read(&mut hpk); // Every 'read' effectively contains k = k + 1
            if CTEST {
                hpk[0] = i.to_le_bytes()[0];
            }
            if hpk[0] <= i.to_le_bytes()[0] {
                break;
            }
        }

        // 7: j ← H(ρ)[[k]] ▷ j is a pseudorandom byte that is ≤ i
        let j = hpk[0];

        // 8: ci ← cj
        c.0[i] = c.0[usize::from(j)];

        // 9: c_j ← (−1)^{H(ρ)[i+τ−256]
        let index = i + tau - 256;
        let bite = hpk8[index / 8];
        let shifted = bite >> (index & 0x07);
        c.0[usize::from(j)] = 1 - 2 * i32::from(shifted & 0x01);

        // 10: k ← k + 1   (implicit)

        // 11: end for
    }

    // 12: return c
    debug_assert!(c.0.iter().filter(|e| e.abs() != 0).count() == tau, "Alg 23: bad hamming weight");
    c
}


/// # Algorithm 24: `RejNTTPoly(ρ)` on page 30.
/// Samples a polynomial ∈ `Tq`. Note that this function is only used in the algorithm 26
/// function `expand_a_vartime()`. This latter function operates on `rho` which is a component
/// of the public key passed in the clear. This complicates the (constant) time analysis of
/// `ml_dsa::key_gen_vartime()`, `ml_dsa::sign_start()` and `ml_dsa::verify_start()`.
///
/// **Input**: A seed `ρ ∈ {0,1}^{272}`.<br>
/// **Output**: An element `a_hat ∈ Tq`.
pub(crate) fn rej_ntt_poly_vartime<const CTEST: bool>(rhos: &[&[u8]]) -> T {
    debug_assert_eq!(rhos.iter().map(|&i| i.len()).sum::<usize>(), 272 / 8, "Alg 24: bad rho size");
    let mut a_hat = T0;
    let mut xof = h128_xof(rhos);

    // 1: j ← 0
    let mut j = 0;

    // 2: c ← 0  (xof has implicit and advancing j)

    // 3: while j < 256 do
    while j < 256 {
        //
        // 4: a_hat[j] ← CoefFromThreeBytes(H128(ρ)[[c]], H128(ρ)[[c + 1]], H128(ρ)[[c + 2]])
        let mut h128pc = [0u8; 3];
        xof.read(&mut h128pc); // implicit c += 3
        let a_hat_j = coef_from_three_bytes_vartime::<CTEST>(h128pc); // gets a result

        // 5: c ← c + 3  (implicit)

        // 6: if a_hat[j] != ⊥ then
        if let Ok(res) = a_hat_j {
            a_hat.0[j] = res; // Good result, save it and carry on

            // 7: j ← j + 1
            j += 1;

            // 8: end if
        }

        // 9: end while
    }

    // 10: return a_hat
    a_hat
}


/// # Algorithm 25 RejBoundedPoly(ρ) on page 31.
/// Samples an element `a ∈ Rq` with coefficients in `[−η, η]` computed via rejection sampling from `ρ`.
///
/// **Input**: A seed `ρ ∈{0,1}^528`. <br>
/// **Output**: A polynomial `a ∈ Rq`.
///
/// # Panics
/// In debug, requires correctly sized `p`.
pub(crate) fn rej_bounded_poly_vartime<const CTEST: bool>(eta: i32, rhos: &[&[u8]]) -> R {
    debug_assert_eq!(rhos.iter().map(|&i| i.len()).sum::<usize>(), 528 / 8, "Alg25: bad rho size");
    let mut z = [0u8];
    let mut a = R0;
    let mut xof = h_xof(rhos);

    // 1: j ← 0
    let mut j = 0;

    // 2: c ← 0  c is implicit and advancing in xof

    // 3: while j < 256 do
    while j < 256 {
        //
        // 4: z ← H(ρ)[[c]]
        xof.read(&mut z);

        // 5: z0 ← CoefFromHalfByte(z mod 16, η)
        let z0 = coef_from_half_byte_vartime::<CTEST>(eta, z[0] & 0x0f);

        // 6: z1 ← CoefFromHalfByte(⌊z/16⌋, η)
        let z1 = coef_from_half_byte_vartime::<CTEST>(eta, z[0] >> 4);

        // 7: if z0 != ⊥ then
        if let Ok(z0) = z0 {
            //
            // 8: a_j ← z0
            a.0[j] = z0;

            // 9: j ← j + 1
            j += 1;

            // 10: end if
        }

        // 11: if z1 != ⊥ and j < 256 then
        if let Ok(z1) = z1 {
            if j < 256 {
                //
                // 12: aj ← z1
                a.0[j] = z1;

                // 13: j ← j + 1
                j += 1;

                // 14: end if
            }
        }

        // 15: c ← c + 1  (implicit)

        // 16: end while
    }

    // 17: return a
    a
}


/// # Algorithm 26 ExpandA(ρ) on page 31.
/// Samples a k × ℓ matrix `A_hat` of elements of `T_q`. This function operates solely on `rho`
/// which is a component of the public key passed in the clear. This complicates the (constant)
/// timing analysis of `ml_dsa::key_gen()_vartime`, `ml_dsa::sign_start()` and
/// `ml_dsa::verify_start()`.
///
/// **Input**: `ρ ∈ {0,1}^256`. <br>
/// **Output**: Matrix `A_hat`
#[allow(clippy::cast_possible_truncation)] // s and r
pub(crate) fn expand_a_vartime<const CTEST: bool, const K: usize, const L: usize>(
    rho: &[u8; 32],
) -> [[T; L]; K] {
    // 1: for r from 0 to k − 1 do
    // 2:   for s from 0 to ℓ − 1 do
    // 3:     A_hat[r, s] ← RejNTTPoly(ρ||IntegerToBits(s, 8)||IntegerToBits(r, 8))
    // 4:   end for
    // 5: end for

    let cap_a_hat: [[T; L]; K] = core::array::from_fn(|r| {
        core::array::from_fn(|s| rej_ntt_poly_vartime::<CTEST>(&[&rho[..], &[s as u8], &[r as u8]]))
    });
    cap_a_hat
}


/// # Algorithm 27: `ExpandS(ρ)` on page 32.
/// Samples vectors `s1 ∈ R^ℓ_q` and `s2 ∈ R^k_q`, each with coefficients in the interval `[−η, η]`.
/// Note that this function is only used in the `ml_dsa::keygen_vartime()` functionality using the
/// `rho_prime` private random seed. It is not exposed to untrusted input.
///
/// **Input**: `ρ ∈ {0,1}^512` <br>
/// **Output**: Vectors `s1`, `s2` of polynomials in `Rq`.
///
/// # Errors
/// Returns an error on out of range s1 s2 coefficients.
/// Propagates any errors generated by called functions.
#[allow(clippy::cast_possible_truncation)] // r and r+L
pub(crate) fn expand_s_vartime<const CTEST: bool, const K: usize, const L: usize>(
    eta: i32, rho: &[u8; 64],
) -> ([R; L], [R; K]) {
    //
    // 1: for r from 0 to ℓ − 1 do
    // 2: s1[r] ← RejBoundedPoly(ρ||IntegerToBits(r, 16))
    // 3: end for
    let s1: [R; L] =
        core::array::from_fn(|r| rej_bounded_poly_vartime::<CTEST>(eta, &[rho, &[r as u8], &[0]]));

    // 4: for r from 0 to k − 1 do
    // 5: s2[r] ← RejBoundedPoly(ρ||IntegerToBits(r + ℓ, 16))
    // 6: end for
    let s2: [R; K] = core::array::from_fn(|r| {
        rej_bounded_poly_vartime::<CTEST>(eta, &[rho, &[(r + L) as u8], &[0]])
    });

    // 7: return (s_1 , s_2)
    debug_assert!(s1.iter().all(|r| is_in_range(r, eta, eta)), "Alg 27: s1 out of range");
    debug_assert!(s2.iter().all(|r| is_in_range(r, eta, eta)), "Alg 27: s2 out of range");
    (s1, s2)
}


/// # Algorithm 28: `ExpandMask(ρ,µ)` from page 32.
/// Samples a vector `s ∈ R^ℓ_q` such that each polynomial `s_j` has coefficients between −γ1 + 1 and γ1.
/// This function is not exposed to untrusted input.
///
/// **Input**: A bit string `ρ ∈ {0,1}^512` and a non-negative integer `µ`. <br>
/// **Output**: Vector `s ∈ R^ℓ_q`.
pub(crate) fn expand_mask<const L: usize>(gamma1: i32, rho: &[u8; 64], mu: u16) -> [R; L] {
    let mut s = [R0; L];
    let mut v = [0u8; 32 * 20];

    // 1: c ← 1 + bitlen (γ1 − 1) ▷ γ1 is always a power of 2
    let c = 1 + bit_length(gamma1 - 1); // c will either be 18 or 20
    debug_assert!((c == 18) | (c == 20), "Alg 28: illegal c");

    // 2: for r from 0 to ℓ − 1 do
    for r in 0..u16::try_from(L).unwrap() {
        //
        // 3: n ← IntegerToBits(µ + r, 16)
        debug_assert!((mu + r < 512), "Alg 28: mu + r out of range");
        let n = mu + r;

        // 4: v ← (H(ρ||n)[[32rc]], H(ρ||n)[[32rc+1]], ... , H(ρ||n)[[32rc+32c − 1]])
        let mut xof = h_xof(&[rho, &n.to_le_bytes()]);
        xof.read(&mut v);

        // 5: s[r] ← BitUnpack(v, γ1 − 1, γ1)
        s[r as usize] = bit_unpack(&v[0..32 * c], gamma1 - 1, gamma1).expect("cannot fail");
        debug_assert!(
            s.iter().all(|r| is_in_range(r, gamma1, gamma1)),
            "Alg 28: s coeff out of range"
        );

        // 6: end for
    }

    // 7: return s
    s
}

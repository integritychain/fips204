// This file implements functionality from FIPS 204 section 8.3 Hashing and Pseudorandom Sampling

use crate::conversion::{bit_unpack, coeff_from_half_byte, coeff_from_three_bytes};
use crate::helpers::{bit_length, is_in_range};
use crate::types::{Ph, R, R0, T, T0};
use sha2::{Digest, Sha256, Sha512};
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
/// Samples a polynomial `c ∈ Rq` with coefficients from `{−1, 0, 1}` and Hamming
/// weight `τ`. This function is used during signing, but only operates on a
/// portion of the non-secret output `c_tilde` element within the signature, so
/// need not be constant-time in normal operation. To support constant-time `dudect`
/// measurements through the `dudect_keygen_sign_with_rng()` function exposed when
/// the `dudect` feature is enabled, the CTEST value would be set to `true` to
/// effectively bypass some of the loop decisions.
///
/// **Input**: A seed `ρ ∈{0,1}^256` <br>
/// **Output**: A polynomial `c` in `Rq`.
pub(crate) fn sample_in_ball<const CTEST: bool>(tau: i32, rho: &[u8]) -> R {
    let tau = usize::try_from(tau).expect("cannot fail");
    //let mut xof = hhh_xof(&[rho]).finalize_xof();

    // 1: c ← 0
    let mut c = R0;

    // 2: ctx ← H.Init()
    // 3: ctx ← H.Absorb(ctx, 𝜌)
    let mut h_ctx = h_xof(&[rho]); // init and absorb

    // 4: (ctx, 𝑠) ← H.Squeeze(ctx, 8)
    // 5: ℎ ← BytesToBits(𝑠)
    let mut h = [0u8; 8];
    h_ctx.read(&mut h); // Save the first 8 bytes for step 9

    // 6: for 𝑖 from 256 − 𝜏 to 255 do
    for i in (256 - tau)..=255 {
        //
        // 7: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
        let mut j = [i.to_le_bytes()[0]]; // remove timing variability
        if !CTEST {
            h_ctx.read(&mut j);
        };

        // 8: while 𝑗 > 𝑖 do
        while usize::from(j[0]) > i {
            // 9: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
            h_ctx.read(&mut j);

            // 10: end while
        }

        // 11: ci ← cj
        c.0[i] = c.0[usize::from(j[0])];

        // 12: c_j ← (−1)^{H(ρ)[i+τ−256]
        let index = i + tau - 256;
        let bite = h[index / 8];
        let shifted = bite >> (index & 0x07);
        c.0[usize::from(j[0])] = 1 - 2 * i32::from(shifted & 0x01);

        // 13: end for
    }

    // slightly redundant...
    debug_assert!(
        c.0.iter().map(|&e| usize::from(e != 0)).sum::<usize>() == tau,
        "Alg 23: bad hamming weight (a)"
    );
    debug_assert!(
        c.0.iter().map(|&e| e & 1).sum::<i32>() == tau.try_into().expect("cannot fail"),
        "Alg 23: bad hamming weight (b)"
    );

    // 14: return c
    c
}


/// # Algorithm 24: `RejNTTPoly(ρ)` on page 30.
/// Samples a polynomial ∈ `Tq`. The `CTEST` generic is only passed through to the
/// `coef_from_three_bytes()` leaf function such that this logic becomes constant-time.
///
/// **Input**: A seed `ρ ∈ {0,1}^{272}`.<br>
/// **Output**: An element `a_hat ∈ Tq`.
pub(crate) fn rej_ntt_poly<const CTEST: bool>(rhos: &[&[u8]]) -> T {
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
        let a_hat_j = coeff_from_three_bytes::<CTEST>(h128pc); // gets a result

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
/// Samples an element `a ∈ Rq` with coefficients in `[−η, η]` computed via rejection
/// sampling from `ρ`. The `CTEST` generic is only passed through to the
/// `coef_from_half_byte()` leaf function such that this logic becomes constant-time.
///
/// **Input**: A seed `ρ ∈{0,1}^528`. <br>
/// **Output**: A polynomial `a ∈ Rq`.
///
/// # Panics
/// In debug, requires correctly sized `p`.
pub(crate) fn rej_bounded_poly<const CTEST: bool>(eta: i32, rhos: &[&[u8]]) -> R {
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
        let z0 = coeff_from_half_byte::<CTEST>(eta, z[0] & 0x0f);

        // 6: z1 ← CoefFromHalfByte(⌊z/16⌋, η)
        let z1 = coeff_from_half_byte::<CTEST>(eta, z[0] >> 4);

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
/// Samples a k × ℓ matrix `cap_a_hat` of elements of `T_q`. The `CTEST` generic is
/// only passed through to the `rej_ntt_poly()` leaf function such that this logic
/// becomes constant-time.
///
/// **Input**: `ρ ∈ {0,1}^256`. <br>
/// **Output**: Matrix `cap_a_hat`
#[allow(clippy::cast_possible_truncation)] // s and r as u8
pub(crate) fn expand_a<const CTEST: bool, const K: usize, const L: usize>(
    rho: &[u8; 32],
) -> [[T; L]; K] {
    // 1: for r from 0 to k − 1 do
    // 2:   for s from 0 to ℓ − 1 do
    // 3:     A_hat[r, s] ← RejNTTPoly(ρ||IntegerToBits(s, 8) || IntegerToBits(r, 8))
    // 4:   end for
    // 5: end for

    let cap_a_hat: [[T; L]; K] = core::array::from_fn(|r| {
        core::array::from_fn(|s| rej_ntt_poly::<CTEST>(&[&rho[..], &[s as u8], &[r as u8]]))
    });
    cap_a_hat
}


/// # Algorithm 27: `ExpandS(ρ)` on page 32.
/// Samples vectors `s1 ∈ R^ℓ_q` and `s2 ∈ R^k_q`, each with coefficients in
/// the interval `[−η, η]`. The `CTEST` generic is only passed through to the
/// `rej_bounded_poly()` leaf function such that this logic becomes constant-time.
///
/// **Input**: `ρ ∈ {0,1}^512` <br>
/// **Output**: Vectors `s1`, `s2` of polynomials in `Rq`.
///
/// # Errors
/// Returns an error on out of range s1 s2 coefficients.
/// Propagates any errors generated by called functions.
#[allow(clippy::cast_possible_truncation)] // r and r+L
pub(crate) fn expand_s<const CTEST: bool, const K: usize, const L: usize>(
    eta: i32, rho: &[u8; 64],
) -> ([R; L], [R; K]) {
    //
    // 1: for r from 0 to ℓ − 1 do
    // 2: s1[r] ← RejBoundedPoly(ρ || IntegerToBits(r, 16))
    // 3: end for
    let s1: [R; L] =
        core::array::from_fn(|r| rej_bounded_poly::<CTEST>(eta, &[rho, &[r as u8], &[0]]));

    // 4: for r from 0 to k − 1 do
    // 5: s2[r] ← RejBoundedPoly(ρ || IntegerToBits(r + ℓ, 16))
    // 6: end for
    let s2: [R; K] =
        core::array::from_fn(|r| rej_bounded_poly::<CTEST>(eta, &[rho, &[(r + L) as u8], &[0]]));

    // 7: return (s_1 , s_2)
    debug_assert!(s1.iter().all(|r| is_in_range(r, eta, eta)), "Alg 27: s1 out of range");
    debug_assert!(s2.iter().all(|r| is_in_range(r, eta, eta)), "Alg 27: s2 out of range");
    (s1, s2)
}


/// # Algorithm 28: `ExpandMask(ρ,µ)` from page 32.
/// Samples a vector `s ∈ R^ℓ_q` such that each polynomial `s_j` has coefficients
/// between `−γ_1 + 1` and `γ_1`. This function is not exposed to untrusted input.
///
/// **Input**: A bit string `ρ ∈ {0,1}^512` and a non-negative integer `µ`. <br>
/// **Output**: Vector `s ∈ R^ℓ_q`.
pub(crate) fn expand_mask<const L: usize>(gamma1: i32, rho: &[u8; 64], mu: u16) -> [R; L] {
    let mut s = [R0; L];
    let mut v = [0u8; 32 * 20]; // leaving a few bytes on the table

    // 1: c ← 1 + bitlen (γ_1 − 1)    ▷ γ_1 is always a power of 2
    let c = 1 + bit_length(gamma1 - 1); // c will either be 18 or 20
    debug_assert!((c == 18) || (c == 20), "Alg 28: illegal c");

    // 2: for r from 0 to ℓ − 1 do
    for r in 0..u16::try_from(L).expect("cannot fail") {
        //
        // 3: n ← IntegerToBits(µ + r, 16)
        let n = mu + r; // This will perform overflow check in debug, which removes need for above assert

        // 4: v ← (H(ρ || n)[[32rc]], H(ρ || n)[[32rc+1]], ..., H(ρ || n)[[32rc+32c − 1]])
        let mut xof = h_xof(&[rho, &n.to_le_bytes()]);
        xof.read(&mut v);

        // 5: s[r] ← BitUnpack(v, γ_1 − 1, γ_1)
        s[r as usize] = bit_unpack(&v[0..32 * c], gamma1 - 1, gamma1).expect("cannot fail");
        debug_assert!(
            s.iter().all(|r| is_in_range(r, gamma1 - 1, gamma1)),
            "Alg 28: s coeff out of range"
        );

        // 6: end for
    }

    // 7: return s
    s
}


pub(crate) fn hash_message(message: &[u8], ph: &Ph, phm: &mut [u8; 64]) -> ([u8; 11], usize) {
    match ph {
        Ph::SHA256 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            {
                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, message);
                phm[0..32].copy_from_slice(&hasher.finalize());
                32
            },
        ),
        Ph::SHA512 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            {
                let mut hasher = Sha512::new();
                Digest::update(&mut hasher, message);
                phm.copy_from_slice(&hasher.finalize());
                64
            },
        ),
        Ph::SHAKE128 => (
            [
                0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
            ],
            {
                let mut hasher = Shake128::default();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                reader.read(phm);
                64
            },
        ),
    }
}

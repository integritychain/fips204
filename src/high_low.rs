use crate::helpers::{full_reduce, mod_pm, partial_reduce};
use crate::types::Zq;
use crate::{D, QI, QU};


// This file implements functionality from FIPS 204 section 8.4 High Order / Low Order Bits and Hints


/// Algorithm 29: `Power2Round(r)` on page 34.
/// Decomposes `r` into `(r1, r0)` such that `r ≡ r1*2^d + r0 mod q`.
///
/// Input: `r ∈ Zq`. <br>
/// Output: Integers `(r1, r0)`.
pub(crate) fn power2round(r: Zq) -> (Zq, Zq) {
    // 1: r+ ← r mod q
    // 2: r0 ← r+ mod±2^d
    // 3: return ((r+ − r0)/2^d, r0)
    let r = full_reduce(r);
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    let r0 = r - (r1 << D);
    (r1, r0)
}


/// Algorithm 30: `Decompose(r)` on page 34.
/// Decomposes `r` into `(r1, r0)` such that `r ≡ r1(2γ2) + r0 mod q`.
///
/// Input: `r ∈ Zq` <br>
/// Output: Integers `(r1, r0)`.
pub(crate) fn decompose(gamma2: i32, r: Zq) -> (Zq, Zq) {
    // 1: r+ ← r mod q
    let rp = full_reduce(r);
    // 2: r0 ← r+ mod±(2γ_2)
    let mut r0 = mod_pm(rp, 2 * gamma2 as u32);
    let mut r1 = 0;
    // 3: if r+ − r0 = q − 1 then
    if (rp - r0) == (QU as i32 - 1) {
        // 4: r1 ← 0
        // *r1 = 0;
        // 5: r0 ← r0 − 1
        r0 -= 1;
    } else {
        // 6: else r_1 ← (r+ − r0)/(2γ2)
        r1 = (rp - r0) / (2 * gamma2 as i32);
        // 7: end if
    }
    (r1, r0)
  //  debug_assert_eq!(rp, *r1 * 2 * gamma2 as i32 + *r0);
    // let r = full_reduce(r);
    // assert!(r < QI);
    // assert!(r >= 0);
    // //let r = r.rem_euclid(QI);
    // *r1 = (r + 127) >> 7;
    // *r1 = (*r1 * 1025 + (1 << 21)) >> 22;
    // *r1 &= 15;
    //
    // *r0  = r - *r1 * 2 * gamma2 as i32;
    // *r0 = *r0 - ((((QI - 1) / 2 - *r0) >> 31) & QI);
}


/// Algorithm 31: `HighBits(r)` on page 34.
/// Returns `r1` from the output of `Decompose(r)`.
///
/// Input: `r ∈ Zq` <br>
/// Output: Integer `r1`.
pub(crate) fn high_bits(gamma2: i32, r: Zq) -> Zq {
    // 1: (r1, r0) ← Decompose(r)
    let (r1, _r0) = decompose(gamma2, r);
    // 2: return r1
    r1
}


/// Algorithm 32: `LowBits(r)` on page 35.
/// Returns r0 from the output of Decompose (r).
///
/// Input: r ∈ Zq <br>
/// Output: Integer r0.
pub(crate) fn low_bits(gamma2: i32, r: Zq) -> Zq {
    // 1: (r1, r0) ← Decompose(r)
    let (_r1, r0) = decompose(gamma2, r);
    // 2: return r0
    r0
}


/// Algorithm 33: `MakeHint(z, r)` on page 35.
/// Compute hint bit indicating whether adding `z` to `r` alters the high bits of `r`.
///
/// Input: `z`, `r` ∈ `Zq` <br>
/// Output: Boolean
pub(crate) fn make_hint(gamma2: i32, z: Zq, r: Zq) -> bool {
    // 1: r1 ← HighBits(r)
    let r1 = high_bits(gamma2, r);
    // 2: v1 ← HighBits(r + z)
    let v1 = high_bits(gamma2, partial_reduce(r + z));
    // 3: return [[r1 != v1]]
    r1 != v1
}


/// Algorithm 34: `UseHint(h, r)` on page 35.
/// Returns the high bits of `r` adjusted according to hint `h`
///
/// Input:boolean `h`, `r` ∈ `Zq` <br>
/// Output: `r1` ∈ `Z` with `0 ≤ r1 ≤ (q − 1)/(2*γ_2)`
pub(crate) fn use_hint(gamma2: i32, h: Zq, r: Zq) -> Zq {
    // 1: m ← (q− 1)/(2*γ_2)
    let m = (QI - 1) / (2 * gamma2);
    // 2: (r1, r0) ← Decompose(r)
    let (r1, r0) = decompose(gamma2, r);
    // 3: if h = 1 and r0 > 0 return (r1 + 1) mod m
    if (h == 1) & (r0 > 0) {
        return (r1 + 1).rem_euclid(m);
    }
    // 4: if h = 1 and r0 ≤ 0 return (r1 − 1) mod m
    if (h == 1) & (r0 <= 0) {
        return (r1 - 1).rem_euclid(m);
    }
    // 5: return r1
    r1
}

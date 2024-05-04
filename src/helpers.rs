use crate::types::R;
use crate::{Q, ZETA};

// Some arith routines leverage dilithium https://github.com/PQClean/PQClean/tree/master/crypto_sign


/// # Macro ensure!()
/// If the condition is not met, return an error message. Borrowed from the `anyhow` crate.
/// Pervasive use of this macro hits performance around 3%
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($msg);
        }
    };
}

pub(crate) use ensure; // make available throughout crate


/// Ensure all coefficients of polynomial `w` are within -lo to +hi (inclusive)
pub(crate) fn is_in_range(w: &R, lo: i32, hi: i32) -> bool {
    w.iter().all(|&e| (e >= -lo) && (e <= hi)) // success is CT, failure vartime
}


/// Partial Barrett-style reduction
const M: i128 = (1 << 64) / (Q as i128);
#[allow(clippy::inline_always, clippy::cast_possible_truncation)]
#[inline(always)]
pub(crate) const fn partial_reduce64(a: i64) -> i32 {
    let q = (a as i128 * M) >> 64;
    (a - (q as i64) * (Q as i64)) as i32
}

/// Partially reduce a signed 32-bit value mod Q ---> `-Q <~ result <~ Q`
// Considering the positive case for `a`, bits 23 and above can be loosely
// viewed as the 'number of Q' contained within `a` (with some rounding-down
// error). So, increment these bits and then subtract off the corresponding
// number of Q. The result is within (better than) -Q < res < Q. This
// approach also works for negative values. For the extreme positive `a`
// result, consider all bits set except for position 22 so the increment
// cannot generate a carry (and thus we have maximum rounding-down error
// accumulated), or a = 2**31 - 2**22 - 1, which then suggests (0xFF) Q to
// be subtracted. Then, a - (a >> 23)*Q is 6283008 or 2**23 - 2**21 - 2**8.
// The negative result works out to -6283008. Note Q is 2**23 - 2**13 + 1.  TODO: Recheck #s
#[inline(always)]
#[allow(clippy::inline_always)]
pub(crate) const fn partial_reduce32(a: i32) -> i32 {
    let x = (a + (1 << 22)) >> 23;
    let res = a - x * Q;
    debug_assert!(res.abs() < (1 << 23) - (1 << 21) - (1 << 8));
    res
}


pub(crate) const fn full_reduce32(a: i32) -> i32 {
    let x = partial_reduce32(a); // puts us within better than -Q to +Q
    x + ((x >> 31) & Q) // add Q if negative
}

// Note: this is only used on 'fixed' security parameters (not secret values), so as not to impact CT
/// Bit length required to express `a` in bits
pub(crate) const fn bit_length(a: i32) -> usize { a.ilog2() as usize + 1 }


/// Mod +/- see definition on page 6.
/// If α is a positive integer and m ∈ Z or m ∈ `Z_α` , then m mod± α denotes the unique
/// element m′ ∈ Z in the range −α/2 < m′ ≤ α/2 such that m and m′ are congruent
/// modulo α.  'ready to optimize'
pub(crate) fn center_mod(m: i32) -> i32 {
    let t = full_reduce32(m);
    let over2 = (Q / 2) - t; // check if t is larger than Q/2
    t - ((over2 >> 31) & Q) // sub Q if over2 is negative
}


/// Matrix by vector multiplication; See top of page 10, first row: `w_hat` = `A_hat` mul `u_hat`
#[must_use]
pub(crate) fn mat_vec_mul<const K: usize, const L: usize>(
    a_hat: &[[[i32; 256]; L]; K], u_hat: &[[i32; 256]; L],
) -> [[i32; 256]; K] {
    let mut w_hat = [[0i32; 256]; K];
    for i in 0..K {
        #[allow(clippy::needless_range_loop)] // clarity
        for j in 0..L {
            w_hat[i].iter_mut().enumerate().for_each(|(m, e)| {
                *e = partial_reduce64(
                    i64::from(*e) + i64::from(a_hat[i][j][m]) * i64::from(u_hat[j][m]),
                );
            });
        }
    }
    w_hat
}


/// Vector addition; See bottom of page 9, second row: `z_hat` = `u_hat` + `v_hat`
#[must_use]
pub(crate) fn vec_add<const K: usize>(vec_a: &[R; K], vec_b: &[R; K]) -> [R; K] {
    let mut result = [[0i32; 256]; K];
    for i in 0..vec_a.len() {
        for j in 0..vec_a[i].len() {
            result[i][j] = vec_a[i][j] + vec_b[i][j]; //partial_reduce(vec_a[i][j] + vec_b[i][j]);
        }
    }
    result
}


pub(crate) fn infinity_norm<const ROW: usize, const COL: usize>(w: &[[i32; COL]; ROW]) -> i32 {
    let mut result = 0; // no early exit
    for row in w {
        for element in row {
            let z_q = center_mod(*element).abs();
            result = if z_q > result { z_q } else { result }; // TODO: check CT
        }
    }
    result
}


// ----- The following functions only run at compile time (thus, not CT etc) -----

/// HAC Algorithm 14.76 Right-to-left binary exponentiation mod Q.
const fn pow_mod_q(g: i32, e: u8) -> i32 {
    let g = g as i64;
    let mut result = 1;
    let mut s = g;
    let mut e = e;
    while e != 0 {
        if e & 1 != 0 {
            result = partial_reduce64(result * s) as i64;
        };
        e >>= 1;
        if e != 0 {
            s = partial_reduce64(s * s) as i64;
        };
    }
    full_reduce32(partial_reduce64(result))
}


const fn gen_zeta_table() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        result[i] = pow_mod_q(ZETA, i.to_le_bytes()[0].reverse_bits());
        i += 1;
    }
    result
}

#[allow(dead_code)]
pub(crate) static ZETA_TABLE: [i32; 256] = gen_zeta_table();

///////////////////////

#[allow(dead_code)]
const QINV: i64 = 58_728_449;  // (Q * QINV) % 2**32 = 1

#[allow(dead_code, clippy::cast_possible_truncation)]
pub(crate) const fn mont_reduce(a: i64) -> i32 {
    let t = a.wrapping_mul(QINV) as i32;
    let t = (a - (t as i64).wrapping_mul(Q as i64)) >> 32;
    debug_assert!(t < (Q as i64));
    debug_assert!(-(Q as i64) < t);
    t as i32
}

#[allow(dead_code)]
pub(crate) static ZETA_TABLE_MONT: [i32; 256] = gen_zeta_table_mont();

#[allow(clippy::cast_possible_truncation)]
const fn gen_zeta_table_mont() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut i = 0_usize;
    while i < 256 {
        let result_norm = pow_mod_q(ZETA, i.to_le_bytes()[0].reverse_bits());
        let result_mont = (result_norm as i64).wrapping_mul(2i64.pow(32)).rem_euclid(Q as i64) as i32;
        result[i] = result_mont;
        i += 1;
    }
    result
}

//////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_zeta() {
        let zeta_target: [i32; 256] = [
            0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
            1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
            2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
            -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
            2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
            -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
            -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
            811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
            -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
            -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
            3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
            -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
            -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
            -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
            189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
            1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
            2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
            266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
            900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
            -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
            342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
            2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
            -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
            -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
            -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
            -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
            -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
            -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
            -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
            -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
            -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
            -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
        ];
        //println!("my zeta_norm {:?}", ZETA_TABLE);
        for i in 7..256 {
            assert_eq!(ZETA_TABLE_MONT[i], zeta_target[i], "i={}    left={}    target={}", i, ZETA_TABLE_MONT[i], zeta_target[i]);

        }
    }
}

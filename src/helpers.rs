use crate::types::{Zero, R};
use crate::{QI, QU, ZETA};


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


/// Ensure polynomial w is within -lo to +hi (inclusive)
pub(crate) fn is_in_range(w: &R, lo: i32, hi: i32) -> bool {
    w.iter().all(|&e| (e >= -lo) & (e <= hi))
}


/// Partial Barrett-style reduction
const M: i128 = 2i128.pow(64) / (QI as i128);
#[allow(clippy::inline_always, clippy::cast_possible_truncation)]
#[inline(always)]
pub(crate) const fn partial_reduce64(a: i64) -> i32 {
    let q = (a as i128 * M) >> 64;
    (a - (q as i64) * (QI as i64)) as i32
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
// The negative result works out to -6283008. Note Q is 2**23 - 2**13 + 1.  TODO: Recheck
#[inline(always)]
#[allow(clippy::inline_always)]
pub(crate) const fn partial_reduce32(a: i32) -> i32 {
    let x = (a + (1 << 22)) >> 23;
    let res = a - x * QI;
    debug_assert!(res.abs() < 2i32.pow(23) - 2i32.pow(21) - 2i32.pow(8));
    res
}

#[allow(dead_code)]
pub(crate) const fn full_reduce32(a: i32) -> i32 {
    let x = partial_reduce32(a); // puts us within -Q to +Q
    x + ((x >> 31) & QI) // add Q if negative
}

/// Bit length required to express `a` in bits
pub const fn bit_length(a: i32) -> usize { a.ilog2() as usize + 1 }


/// Mod +/- see definition on page 6.
/// If α is a positive integer and m ∈ Z or m ∈ `Z_α` , then m mod± α denotes the unique
/// element m′ ∈ Z in the range −α/2 < m′ ≤ α/2 such that m and m′ are congruent
/// modulo α.  'ready to optimize'
// pub fn mod_pm(m: i32, a: u32) -> i32 {
//     let a = i32::try_from(a).unwrap();
//     let t = m.rem_euclid(a);
//     if t <= (a / 2) {
//         t
//     } else {
//         t - a
//     }
// }

pub fn mod_pm2(m: i32, a: u32) -> i32 {
    let a = i32::try_from(a).unwrap();
    //let t = m.rem_euclid(a);
    let t = partial_reduce32(m);
    // t + ((t >> 31) & QI) // add Q if negative

    if t <= (a / 2) {
        t
    } else {
        t - a
    }
}


/// Matrix by vector multiplication; See top of page 10, first row: `w_hat` = `A_hat` mul `u_hat`
#[must_use]
pub(crate) fn mat_vec_mul<const K: usize, const L: usize>(
    a_hat: &[[[i32; 256]; L]; K], u_hat: &[[i32; 256]; L],
) -> [[i32; 256]; K] {
    let mut w_hat = [[0i32; 256]; K];
    for i in 0..K {
        #[allow(clippy::needless_range_loop)]
        for j in 0..L {
            let mut tmp = [0i32; 256];
            tmp.iter_mut().enumerate().for_each(|(m, e)| {
                *e = partial_reduce64(i64::from(a_hat[i][j][m]) * i64::from(u_hat[j][m]));
            });
            for k in 0..256 {
                w_hat[i][k] = partial_reduce32(w_hat[i][k] + tmp[k]);
            }
        }
    }
    w_hat
}

/// Vector addition; See bottom of page 9, second row: `z_hat` = `u_hat` + `v_hat`
#[must_use]
pub(crate) fn vec_add<const K: usize>(vec_a: &[R; K], vec_b: &[R; K]) -> [R; K] {
    let mut result = [R::zero(); K];
    for i in 0..vec_a.len() {
        for j in 0..vec_a[i].len() {
            result[i][j] = vec_a[i][j] + vec_b[i][j]; //partial_reduce(vec_a[i][j] + vec_b[i][j]);
        }
    }
    result
}


pub fn infinity_norm<const ROW: usize, const COL: usize>(w: &[[i32; COL]; ROW]) -> i32 {
    let mut result = 0;
    for row in w {
        for element in row {
            let z_q = mod_pm2(*element, QU).abs();
            result = if z_q > result { z_q } else { result };
        }
    }
    result
}


/// HAC Algorithm 14.76 Right-to-left binary exponentiation mod Q.
#[must_use]
const fn pow_mod_q(g: i32, e: u8) -> i32 {
    let g = g as i64;
    let mut result = 1;
    let mut s = g;
    let mut e = e;
    while e != 0 {
        if e & 1 != 0 {
            result = (result * s).rem_euclid(QI as i64);
        };
        e >>= 1;
        if e != 0 {
            s = (s * s).rem_euclid(QI as i64);
        };
    }
    partial_reduce64(result)
}


#[allow(clippy::cast_possible_truncation)] // temporary
const fn gen_zeta_table() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        result[i] = pow_mod_q(ZETA, (i as u8).reverse_bits());
        i += 1;
    }
    result
}

pub(crate) static ZETA_TABLE: [i32; 256] = gen_zeta_table();

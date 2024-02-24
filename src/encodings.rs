//! This file implements functionality from FIPS 204 section 8.2 Encodings of ML-DSA Keys and Signatures

use crate::helpers::{bitlen, ensure, is_in_range};
use crate::types::{Zero, R};
use crate::{
    conversion::{
        bit_pack, bit_unpack, hint_bit_pack, hint_bit_unpack, simple_bit_pack, simple_bit_unpack,
    },
    D, QU,
};


/// Algorithm 16: `pkEncode(ρ, t1)` on page 25.
/// Encodes a public key for ML-DSA into a byte string.
///
/// Input: `ρ ∈ {0, 1}^256`, `t1 ∈ Rk` with coefficients in `[0, 2^{bitlen(q−1) − d} - 1]`. <br>
/// Output: Public key `pk ∈ B^{32+32k(bitlen (q−1)−d)}`.
///
/// # Errors
/// Returns an error ........ TKTK
#[allow(clippy::cast_possible_truncation)] // blqd as u32; note debug_assert
pub(crate) fn pk_encode<const K: usize, const PK_LEN: usize>(
    p: &[u8; 32], t1: &[R; K],
) -> Result<[u8; PK_LEN], &'static str> {
    let blqd = bitlen(QU as usize - 1) - D as usize;
    debug_assert!(blqd < u32::MAX as usize, "Alg 16: bldq too large");
    let mut pk = [0u8; PK_LEN];

    // 1: pk ← BitsToBytes(ρ)
    pk[0..32].copy_from_slice(p);
    // 2: for i from 0 to k − 1 do
    for i in 0..K {
        // 3: pk ← pk || SimpleBitPack (t1[i], 2^{bitlen(q−1)−d}-1)
        simple_bit_pack(
            &t1[i],
            2u32.pow(blqd as u32) - 1,
            &mut pk[32 + 32 * i * blqd..32 + 32 * (i + 1) * blqd],
        )?;
        // 4: end for
    }
    // 5: return pk
    Ok(pk)
}


/// Algorithm 17: `pkDecode(pk)` on page 25.
/// Reverses the procedure pkEncode.
///
/// Input: Public key `pk ∈ B^{32+32k(bitlen(q−1)−d)}`. <br>
/// Output: `ρ ∈ {0, 1}^256`, `t1 ∈ R^k` with coefficients in `[0, 2^{bitlen(q−1)−d} − 1]`).
///
/// # Errors
/// Returns an error ........ TKTK
#[allow(clippy::cast_possible_truncation)] // blqd as u32; note debug_assert
pub(crate) fn pk_decode<const K: usize, const PK_LEN: usize>(
    pk: &[u8; PK_LEN],
) -> Result<([u8; 32], [R; K]), &'static str> {
    let blqd = bitlen(QU as usize - 1) - D as usize;
    debug_assert!(blqd < u32::MAX as usize, "Alg 17: bldq too large");
    ensure!(pk.len() == 32 + 32 * K * blqd, "Algorithm 17: incorrect pk length");
    let (mut rho, mut t1): ([u8; 32], [R; K]) = ([0u8; 32], [R::zero(); K]);

    // 1: (y, z_0 , . . . , z_{k−1}) ∈ B^{32} × (B^{32(bitlen(q−1)−d))^k} ← pk
    // pull out these fields below
    // 2: ρ ← BytesToBits(y)
    rho.copy_from_slice(&pk[0..32]);
    // 3: for i from 0 to k − 1 do
    for i in 0..K {
        // 4: t1[i] ← SimpleBitUnpack(zi, 2^{bitlen(q−1)−d} − 1)) ▷ This is always in the correct range
        t1[i] = simple_bit_unpack(
            &pk[32 + 32 * i * blqd..32 + 32 * (i + 1) * blqd],
            2u32.pow(blqd as u32) - 1,
        )?;
        // 5: end for
    }
    // 6: return (ρ, t1 )
    ensure!(
        t1.iter().all(|x| is_in_range(x, 0, 2u32.pow(blqd as u32))),
        "Algorithm 17: t1 out of range"
    );
    Ok((rho, t1))
}


/// Algorithm 18: `skEncode(ρ, K,tr, s1, s2, t0)` on page 26.
/// Encodes a secret key for ML-DSA into a byte string.
///
/// Input: `ρ ∈ {0,1}^256`, `K ∈ {0,1}^256`, `tr ∈ {0,1}^512`, <br>
///        `s1 ∈ R^l` with coefficients in `[−η, η]`, <br>
///        `s2 ∈ R^k` with coefficients in `[−η η]`, <br>
///        `t0 ∈ R^k` with coefficients in `[−2^{d-1} + 1, 2^{d-1}]`. <br>
/// Output: Private key, `sk ∈ B^{32+32+64+32·((k+ℓ)·bitlen(2η)+dk)}`
///
/// # Errors
/// Returns an error ........ TKTK
pub fn sk_encode<const K: usize, const L: usize, const SK_LEN: usize>(
    eta: u32, rho: &[u8; 32], k: &[u8; 32], tr: &[u8; 64], s1: &[R; L], s2: &[R; K], t0: &[R; K],
) -> Result<[u8; SK_LEN], &'static str> {
    ensure!(s1.iter().all(|x| is_in_range(x, eta, eta)), "Algorithm 18: s1 out of range");
    ensure!(s2.iter().all(|x| is_in_range(x, eta, eta)), "Algorithm 18: s2 out of range");
    ensure!(
        t0.iter().all(|x| is_in_range(x, 2u32.pow(D - 1) + 1, 2u32.pow(D - 1))),
        "Algorithm 18: t0 out of range"
    );
    let mut sk = [0u8; SK_LEN];
    debug_assert_eq!(
        sk.len(),
        32 + 32 + 64 + 32 * ((K + L) * bitlen(2 * eta as usize) + D as usize * K)
    ); // Useful nonsense? ;)

    // 1: sk ← BitsToBytes(ρ) || BitsToBytes(K) || BitsToBytes(tr)
    sk[0..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(k);
    sk[64..128].copy_from_slice(tr);
    // 2: for i from 0 to ℓ − 1 do
    let start = 128;
    let step = 32 * bitlen(2 * eta as usize);
    for i in 0..L {
        // 3: sk ← sk || BitPack (s1[i], η, η)
        bit_pack(&s1[i], eta, eta, &mut sk[start + i * step..start + (i + 1) * step])?;
        // 4: end for
    }
    // 5: for i from 0 to k − 1 do
    let start = start + L * step;
    for i in 0..K {
        // 6: sk ← sk || BitPack (s2[i], η, η)
        bit_pack(&s2[i], eta, eta, &mut sk[start + i * step..start + (i + 1) * step])?;
        // 7: end for
    }
    // 8: for i from 0 to k − 1 do
    let start = start + K * step;
    let step = 32 * D as usize;
    for i in 0..K {
        // 9: sk ← sk || BitPack (t0[i], [−2^{d-1} + 1, 2^{d-1}] )
        bit_pack(
            &t0[i],
            2u32.pow(D - 1) - 1,
            2u32.pow(D - 1),
            &mut sk[start + i * step..start + (i + 1) * step],
        )?;
        // 10: end for
    }
    // ...just make sure we really hit the end of the sk slice
    debug_assert_eq!(start + K * step, sk.len());
    Ok(sk)
}


/// Algorithm 19: `skDecode(sk)` on page 27.
/// Reverses the procedure skEncode.
///
/// Input: Private key, `sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}` <br>
/// Output: `ρ ∈ {0,1}^256`, `K ∈ {0,1}^256`, `tr ∈ {0,1}^512`, <br>
///    `s1 ∈ R^ℓ`, `s2 ∈ R^k`, `t0 ∈ R^k` with coefficients in `[−2^{d−1} + 1, 2^{d−1}]`.
///
/// # Errors
/// Returns an error ........ TKTK
#[allow(clippy::similar_names, clippy::type_complexity)]
pub(crate) fn sk_decode<const K: usize, const L: usize, const SK_LEN: usize>(
    eta: u32, sk: &[u8; SK_LEN],
) -> Result<([u8; 32], [u8; 32], [u8; 64], [R; L], [R; K], [R; K]), &'static str> {
    let bl = bitlen(2 * eta as usize);
    ensure!(
        sk.len() == 32 + 32 + 64 + 32 * ((L + K) * bl + D as usize * K),
        "Algorithm 19: asdf asdf"
    );
    let (mut rho, mut k, mut tr) = ([0u8; 32], [0u8; 32], [0u8; 64]);
    let (mut s1, mut s2, mut t0) = ([R::zero(); L], [R::zero(); K], [R::zero(); K]);

    // 1: (f, g, h, y_0, . . . , y_{ℓ−1}, z_0, . . . , z_{k−1}, w_0, . . . , w_{k−1)}) ∈
    //    B^32 × B^32 × B^64 × B^{32·bitlen(2η)}^l × B^{32·bitlen(2η)}^k × B^{32d}^k ← sk
    // pull out these fields below
    // 2: ρ ← BytesToBits( f )
    rho.copy_from_slice(&sk[0..32]);
    // 3: K ← BytesToBits(g)
    k.copy_from_slice(&sk[32..64]);
    // 4: tr ← BytesToBits(h)
    tr.copy_from_slice(&sk[64..128]);
    // 5: for i from 0 to ℓ − 1 do
    let start = 128;
    let step = 32 * bl;
    for i in 0..L {
        // 6: s1[i] ← BitUnpack(yi, η, η)   ▷ This may lie outside [−η, η], if input is malformed
        s1[i] = bit_unpack(&sk[start + i * step..start + (i + 1) * step], eta, eta)?;
        // 7: end for
    }
    // 8: for i from 0 to k − 1 do
    let start = start + L * step;
    for i in 0..K {
        // 9: s2[i] ← BitUnpack(zi, η, η) ▷ This may lie outside [−η, η], if input is malformed
        s2[i] = bit_unpack(&sk[start + i * step..start + (i + 1) * step], eta, eta)?;
        // 10: end for
    }
    // 11: for i from 0 to k − 1 do
    let start = start + K * step;
    let step = 32 * D as usize;
    for i in 0..K {
        // 12: t0[i] ← BitUnpack(wi, −2^{d−1} - 1, 2^{d−1})   ▷ This is always in the correct range
        t0[i] = bit_unpack(
            &sk[start + i * step..start + (i + 1) * step],
            2u32.pow(D - 1) - 1,
            2u32.pow(D - 1),
        )?;
        // 13: end for
    }
    // ... just make sure we hit the end of sk slice properly
    ensure!(start + K * step == sk.len(), "Algorithm 19: asdf asdf ");

    // Note spec is not consistent on the range constraints for s1 and s2; this is tighter
    let s1_ok = s1.iter().all(|r| is_in_range(r, eta, eta));
    let s2_ok = s2.iter().all(|r| is_in_range(r, eta, eta));
    let t0_ok = t0.iter().all(|r| is_in_range(r, 2u32.pow(D - 1) + 1, 2u32.pow(D - 1) + 1));
    if s1_ok & s2_ok & t0_ok {
        Ok((rho, k, tr, s1, s2, t0))
    } else {
        Err("Invalid sk_decode deserialization")
    }
}


/// Algorithm 20: `sigEncode(c_tilde, z, h)` on page 28.
/// Encodes a signature into a byte string.
///
/// Input: `c_tilde ∈ {0,1}^2λ`, `z ∈ R^ℓ` with coefficients in `[−1*γ_1 + 1, γ_1]`, `h ∈ R^k_2`. <br>
/// Output: Signature, `σ ∈ B^{λ/4 +l*32*(1+bitlen(γ_1-1)+ω+k}`
///
/// # Errors
/// Returns an error ........ TKTK
pub(crate) fn sig_encode<
    const K: usize,
    const L: usize,
    const LAMBDA: usize,
    const SIG_LEN: usize,
>(
    gamma1: u32, omega: u32, c_tilde: &[u8], z: &[R; L], h: &[R; K],
) -> Result<[u8; SIG_LEN], &'static str> {
    let mut sigma = [0u8; SIG_LEN];
    ensure!(c_tilde.len() == 2 * LAMBDA / 8, "Algoirthm 20: asdf asdf");
    let bl = bitlen(gamma1 as usize - 1);
    ensure!(
        sigma.len() == LAMBDA / 4 + L * 32 * (1 + bl) + omega as usize + K,
        "Algorithm 20: qwer qwer"
    );

    // 1: σ ← BitsToBytes(c_tilde)
    sigma[..2 * LAMBDA / 8].copy_from_slice(c_tilde);
    // 2: for i from 0 to ℓ − 1 do
    let start = 2 * LAMBDA / 8;
    let step = 32 * (1 + bl);
    for i in 0..L {
        // 3: σ ← σ || BitPack (z[i], γ_1 − 1, γ_1)
        bit_pack(&z[i], gamma1 - 1, gamma1, &mut sigma[start + i * step..start + (i + 1) * step])?;
        // 4: end for
    }
    // 5: σ ← σ || HintBitPack (h)
    hint_bit_pack::<K>(omega, h, &mut sigma[start + L * step..])?;
    Ok(sigma)
}


/// Algorithm 21: `sigDecode(σ)` on page 28.
/// Reverses the procedure `sigEncode`.
///
/// Input: Signature, `σ ∈ B^{λ/4+ℓ·32·(1+bitlen (γ_1-1))+ω+k` <br>
/// Output: `c_tilde ∈ {0,1}^2λ`, `z ∈ R^ℓ_q` with coefficients in `[−γ_1 + 1, γ1]`, `h ∈ R^k_2` or `⊥`. <br>
/// Note: `c_tilde` is hardcoded to 256bits since the remainder is 'soon' discarded.
///
/// # Errors
/// Returns an error ........ TKTK
#[allow(clippy::type_complexity)]
pub(crate) fn sig_decode<const K: usize, const L: usize, const LAMBDA: usize>(
    gamma1: u32, omega: u32, sigma: &[u8],
) -> Result<([u8; 64], [R; L], Option<[R; K]>), &'static str> {
    let bl = bitlen(gamma1 as usize - 1);
    // let mut c_tilde = vec![0u8; LAMBDA / 4];
    let mut c_tilde = [0u8; 64]; // TODO: 'optimize'
    let mut z: [R; L] = [R::zero(); L];

    // 1: (ω, x_0, ... , x_{ℓ−1}, y) ∈ B^{λ/4} × Bℓ·32·(1+bitlen(γ_1−1))+ω+k ← σ
    // 2: c_tilde ← BytesToBits(w)
    c_tilde[0..LAMBDA / 4].copy_from_slice(&sigma[0..LAMBDA / 4]);
    // 3: for i from 0 to ℓ − 1 do
    let start = LAMBDA / 4;
    let step = 32 * (bl + 1);
    for i in 0..L {
        // 4: z[i] ← BitUnpack(xi, γ1 − 1, γ1) ▷ This is always in the correct range, as γ1 is a power of 2
        z[i] = bit_unpack(&sigma[start + i * step..start + (i + 1) * step], gamma1 - 1, gamma1)?;
        // 5: end for
    }
    // 6: h ← HintBitUnpack(y)
    let h = hint_bit_unpack::<K>(omega, &sigma[start + L * step..])?;
    // 7: return (c_tilde, z, h)
    Ok((c_tilde, z, Some(h)))
}


/// Algorithm 22: `w1Encode(w1)` on page 28.
/// Encodes a polynomial vector `w1` into a bit string.
///
/// Input: `w1 ∈ R^k` with coefficients in `[0, (q − 1)/(2γ_2) − 1]`.
/// Output: A bit string representation, `w1_tilde ∈ {0,1}^{32k*bitlen((q-1)/(2γ2)−1)`.
///
/// # Errors
/// Returns an error ........ TKTK
pub(crate) fn w1_encode<const K: usize>(
    gamma2: u32, w1: &[R; K], w1_tilde: &mut [u8],
) -> Result<(), &'static str> {
    let qm12gm1 = (QU - 1) / (2 * gamma2) - 1;
    let bl = bitlen(qm12gm1 as usize);
    ensure!(w1.iter().all(|r| is_in_range(r, 0, qm12gm1)), "Agorithm 22: adsf asdf ");

    // 1: w1_tilde ← ()
    // 2: for i from 0 to k − 1 do
    let step = 32 * bl;
    for i in 0..K {
        // 3: w1_tilde ← w1_tilde || BytesToBits (SimpleBitPack (w1[i], (q − 1)/(2γ2) − 1))
        simple_bit_pack(&w1[i], qm12gm1, &mut w1_tilde[i * step..(i + 1) * step])?;
        // 4: end for
    }
    // 5: return w^tilde_1
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pk_encode_decode_roundtrip1() {
        // D=13 K=4 PK_LEN=1312
        let mut random_pk = [0u8; 1312];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        //let mut rho = [0u8; 32];
        //let mut t1 = [[0i32; 256]; 4];
        let (rho, t1) = pk_decode::<4, 1312>(&random_pk).unwrap();
        //let mut res = [0u8; 1312];
        let res = pk_encode::<4, 1312>(&rho, &t1).unwrap();
        assert_eq!(&random_pk[..], res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip2() {
        // D=13 K=6 PK_LEN=1952
        let mut random_pk = [0u8; 1952];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        //let mut rho = [0u8; 32];
        //let mut t1 = [[0i32; 256]; 6];
        let (rho, t1) = pk_decode::<6, 1952>(&random_pk).unwrap();
        //let mut res = [0u8; 1952];
        let res = pk_encode::<6, 1952>(&rho, &t1).unwrap();
        assert_eq!(random_pk, res);
    }

    #[test]
    fn test_pk_encode_decode_roundtrip3() {
        // D=13 K=8 PK_LEN=2592
        let mut random_pk = [0u8; 2592];
        random_pk.iter_mut().for_each(|a| *a = rand::random::<u8>());
        //let mut rho = [0u8; 32];
        //let mut t1 = [[0i32; 256]; 8];
        let (rho, t1) = pk_decode::<8, 2592>(&random_pk).unwrap();
        //let mut res = [0u8; 2592];
        let res = pk_encode::<8, 2592>(&rho, &t1).unwrap();
        assert_eq!(random_pk, res);
    }

    fn get_vec(max: u32) -> [i32; 256] {
        let mut rnd_r = [0i32; 256];
        rnd_r.iter_mut().for_each(|e| *e = rand::random::<i32>().rem_euclid(max as i32));
        rnd_r
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_sk_encode_decode_roundtrip1() {
        // TODO: figure out how to best test this correctly
        //  - should the skDecode function return a result (probably)
        //  - double check the range of the input operands (most are +/- ETA, but last one is 2^d-1)
        //  - maybe need to rework one/two of the conversion functions in a similar fashion

        // D=13 ETA=2 K=4 L=4 SK_LEN=2560
        let (rho, k) = (rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>());
        let mut tr = [0u8; 64];
        tr.iter_mut().for_each(|e| *e = rand::random::<u8>());
        let s1 = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let s2 = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let t0 = [
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
            get_vec(2u32.pow(11)),
        ];
        //let mut sk = [0u8; 2560];
        let sk = sk_encode::<4, 4, 2560>(2, &rho, &k, &tr, &s1, &s2, &t0).unwrap();
        let res = sk_decode::<4, 4, 2560>(2, &sk);
        assert!(res.is_ok());
        let (rho_test, k_test, tr_test, s1_test, s2_test, t0_test) = res.unwrap();

        assert!(
            (rho == rho_test)
                & (k == k_test)
                & (tr == tr_test)
                & (s1 == s1_test)
                & (s2 == s2_test)
                & (t0 == t0_test)
        );
    }

    #[test]
    fn test_sig_roundtrip() {
        // GAMMA1=2^17 K=4 L=4 LAMBDA=128 OMEGA=80
        let c_tilde: Vec<u8> = (0..2 * 128 / 8).map(|_| rand::random::<u8>()).collect();
        let z = [get_vec(2), get_vec(2), get_vec(2), get_vec(2)];
        let h = [get_vec(1), get_vec(1), get_vec(1), get_vec(1)];
        //let mut sigma = [0u8; 2420];
        let sigma = sig_encode::<4, 4, 128, 2420>(2u32.pow(17), 80, &c_tilde, &z, &h).unwrap();
        // let mut c_test = [0u8; 2 * 128 / 8];
        // let mut z_test = [[0i32; 256]; 4];
        // let mut h_test = [[0i32; 256]; 4];
        let (c_test, z_test, h_test) = sig_decode::<4, 4, 128>(2u32.pow(17), 80, &sigma).unwrap();
        //        assert!(res.is_ok());
        assert_eq!(c_tilde[0..8], c_test[0..8]);
        assert_eq!(z, z_test);
        assert_eq!(h, h_test.unwrap());
    }
}

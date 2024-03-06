//! This file implements functionality from FIPS 204 section 5 Key Generation, 6 Signing, 7 Verification

use crate::encodings::{
    pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode,
};
use crate::hashing::{expand_a, expand_mask, expand_s, h_xof, sample_in_ball};
use crate::helpers::{
    bit_length, center_mod, ensure, infinity_norm, mat_vec_mul, partial_reduce32, partial_reduce64,
    vec_add,
};
use crate::high_low::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::ntt::{inv_ntt, ntt};
use crate::types::{ExpandedPrivateKey, ExpandedPublicKey22, Zero, R, T};
use crate::{D, Q};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;


/// Algorithm: 1 `ML-DSA.KeyGen()` on page 15.
/// Generates a public-private key pair.
///
/// **Input**: `rng` a cryptographically-secure random number generator. <br>
/// **Output**: Public key, `pk` ∈ B^{32+32k(bitlen(q−1)−d)},
/// and private key, `sk` ∈ `B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}`
///
/// # Errors
/// Propagates any errors generated by called functions.
pub(crate) fn key_gen<const K: usize, const L: usize, const PK_LEN: usize, const SK_LEN: usize>(
    rng: &mut impl CryptoRngCore, eta: i32,
) -> Result<([u8; PK_LEN], [u8; SK_LEN]), &'static str> {
    //
    // 1: ξ ← {0,1}^{256}    ▷ Choose random seed
    let mut xi = [0u8; 32];
    rng.try_fill_bytes(&mut xi).map_err(|_| "Random number generator failed")?;

    // 2: (ρ, ρ′, K) ∈ {0,1}^{256} × {0,1}^{512} × {0,1}^{256} ← H(ξ, 1024)    ▷ Expand seed
    let mut h = h_xof(&[&xi]);
    let mut rho = [0u8; 32];
    h.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    h.read(&mut rho_prime);
    let mut cap_k = [0u8; 32];
    h.read(&mut cap_k);

    // 3: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 4: (s_1, s_2 ) ← ExpandS(ρ′)
    let (s_1, s_2): ([R; L], [R; K]) = expand_s(eta, &rho_prime)?;

    // 5: t ← NTT−1 (cap_a_hat ◦ NTT(s_1)) + s_2    ▷ Compute t = As1 + s2
    let s_1_hat: [T; L] = ntt(&s_1);
    let as1_hat: [T; K] = mat_vec_mul(&cap_a_hat, &s_1_hat);
    let mut t: [R; K] = inv_ntt(&as1_hat);
    t = vec_add(&t, &s_2);

    // 6: (t_1 , t_0 ) ← Power2Round(t, d)    ▷ Compress t
    let (t_1, t_0): ([R; K], [R; K]) = power2round(&t);

    // 7: pk ← pkEncode(ρ, t_1)
    let pk: [u8; PK_LEN] = pk_encode(&rho, &t_1)?;

    // 8: tr ← H(BytesToBits(pk), 512)
    let mut tr = [0u8; 64];
    let mut h = h_xof(&[&pk]);
    h.read(&mut tr);

    // 9: sk ← skEncode(ρ, K, tr, s_1 , s_2 , t_0 )     ▷ K and tr are for use in signing
    let sk: [u8; SK_LEN] = sk_encode(eta, &rho, &cap_k, &tr, &s_1, &s_2, &t_0)?;

    // 10: return (pk, sk)
    Ok((pk, sk))
}


/// Algorithm 2 ML-DSA.Sign(sk, M) on page 17
/// Generates a signature for a message M. Intuitive flow `result = sign_finish(sign_start())`
///
/// Input: Private key, `sk` ∈ `B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}` and the message `M` ∈ {0,1}^∗ <br>
/// Output: Signature, `σ` ∈ `B^{32+ℓ·32·(1+bitlen(gamma_1 −1))+ω+k}`
pub(crate) fn sign_start<const K: usize, const L: usize, const SK_LEN: usize>(
    eta: i32,
    sk: &[u8; SK_LEN],
    //) -> Result<([u8; 32], [u8; 64], [T; L], [T; K], [T; K], [[T; L]; K]), &'static str> {
) -> Result<ExpandedPrivateKey<K, L>, &'static str> {
    //
    // 1:  (ρ, K, tr, s_1 , s_2 , t_0 ) ← skDecode(sk)
    let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode(eta, sk)?;

    // 2:  s_hat_1 ← NTT(s_1)
    let s_hat_1: [T; L] = ntt(&s_1);

    // 3:  s_hat_2 ← NTT(s_2)
    let s_hat_2: [T; K] = ntt(&s_2);

    // 4:  t_hat_0 ← NTT(t_0)
    let t_hat_0: [T; K] = ntt(&t_0);

    // 5:  cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    Ok(ExpandedPrivateKey { cap_k, tr, s_hat_1, s_hat_2, t_hat_0, cap_a_hat })
}


#[allow(clippy::similar_names, clippy::many_single_char_names)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_finish<
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
>(
    rand_gen: &mut impl CryptoRngCore,
    beta: i32,
    gamma1: i32,
    gamma2: i32,
    omega: i32,
    //    tau: i32, sk: &[u8; SK_LEN], message: &[u8],
    tau: i32,
    esk: &ExpandedPrivateKey<K, L>,
    message: &[u8],
) -> Result<[u8; SIG_LEN], &'static str> {
    //
    // // 1:  (ρ, K, tr, s_1 , s_2 , t_0 ) ← skDecode(sk)
    // let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode(eta, sk)?;
    //
    // // 2:  s_hat_1 ← NTT(s_1)
    // let s_hat_1: [T; L] = ntt(&s_1);
    //
    // // 3:  s_hat_2 ← NTT(s_2)
    // let s_hat_2: [T; K] = ntt(&s_2);
    //
    // // 4:  t_hat_0 ← NTT(t_0)
    // let t_hat_0: [T; K] = ntt(&t_0);
    //
    // // 5:  cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    // let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    let ExpandedPrivateKey { cap_k, tr, s_hat_1, s_hat_2, t_hat_0, cap_a_hat } = esk;

    // 6:  µ ← H(tr||M, 512)    ▷ Compute message representative µ
    let mut h = h_xof(&[tr, message]);
    let mut mu = [0u8; 64];
    h.read(&mut mu);

    // 7:  rnd ← {0,1}^256    ▷ For the optional deterministic variant, substitute rnd ← {0}256
    let mut rnd = [0u8; 32];
    rand_gen.try_fill_bytes(&mut rnd).map_err(|_| "Alg 2: rng fail")?;

    // 8:  ρ′ ← H(K||rnd||µ, 512)    ▷ Compute private random seed
    let mut h = h_xof(&[cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h.read(&mut rho_prime);

    // 9:  κ ← 0    ▷ Initialize counter κ
    let mut k = 0u16;

    // 10: (z, h) ← ⊥    ▷ we will handle ⊥ inline with 'continue'
    let (mut z, mut h) = ([R::zero(); L], [R::zero(); K]);
    let mut c_tilde = [0u8; LAMBDA_DIV4];

    // 11: while (z, h) = ⊥ do    ▷ Rejection sampling loop (with continue for ⊥)
    loop {
        //
        // 12: y ← ExpandMask(ρ′ , κ)
        let y: [R; L] = expand_mask(gamma1, &rho_prime, k)?;

        // 13: w ← NTT−1 (cap_a_hat ◦ NTT(y))
        let y_hat: [T; L] = ntt(&y);
        let a_y_hat: [T; K] = mat_vec_mul(cap_a_hat, &y_hat);
        let w: [R; K] = inv_ntt(&a_y_hat);

        // 14: w_1 ← HighBits(w)            ▷ Signer’s commitment
        let mut w_1: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                w_1[i][j] = high_bits(gamma2, w[i][j]);
            }
        }

        // 15: c_tilde ∈ {0,1}^{2Lambda} ← H(µ || w1Encode(w_1), 2Lambda)     ▷ Commitment hash
        let w1e_len = 32 * K * bit_length((Q - 1) / (2 * gamma2) - 1);
        let mut w1_tilde = [0u8; 1024]; // TODO: Revisit potential waste of 256 bytes
        w1_encode::<K>(gamma2, &w_1, &mut w1_tilde[0..w1e_len])?;
        let mut h15 = h_xof(&[&mu, &w1_tilde[0..w1e_len]]);
        h15.read(&mut c_tilde);

        // 16: (c_tilde_1 , c_tilde_2) ∈ {0,1}^256 × {0,1}^{2Lambda-256} ← c_tilde    ▷ First 256 bits of commitment hash
        let mut c_tilde_1 = [0u8; 32];
        c_tilde_1.copy_from_slice(&c_tilde[0..32]);
        // c_tilde_2 is never used!

        // 17: c ← SampleInBall(c_tilde_1)    ▷ Verifier’s challenge
        let c: R = sample_in_ball(tau, &c_tilde_1)?;

        // 18: c_hat ← NTT(c)
        let c_hat: T = ntt(&[c])[0];

        // 19: ⟨⟨c_s_1 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_1)
        let mut x: [T; L] = [T::zero(); L];
        for (xi, sh1i) in x.iter_mut().zip(s_hat_1.iter()) {
            for (xij, (chj, sh1ij)) in xi.iter_mut().zip(c_hat.iter().zip(sh1i.iter())) {
                *xij = partial_reduce64(i64::from(*chj) * i64::from(*sh1ij));
            }
        }
        let c_s_1 = inv_ntt(&x);

        // 20: ⟨⟨c_s_2 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_2)
        let mut x: [T; K] = [T::zero(); K];
        for (xi, sh2i) in x.iter_mut().zip(s_hat_2.iter()) {
            for (xij, (chj, sh2ij)) in xi.iter_mut().zip(c_hat.iter().zip(sh2i.iter())) {
                *xij = partial_reduce64(i64::from(*chj) * i64::from(*sh2ij));
            }
        }
        let c_s_2 = inv_ntt(&x);

        // 21: z ← y + ⟨⟨c_s_1⟩⟩    ▷ Signer’s response
        for i in 0..L {
            for j in 0..256 {
                z[i][j] = partial_reduce32(y[i][j] + c_s_1[i][j]);
            }
        }

        // 22: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let mut r0: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                r0[i][j] = low_bits(gamma2, partial_reduce32(w[i][j] - c_s_2[i][j]));
            }
        }

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥    ▷ Validity checks
        let z_norm = infinity_norm(&z);
        let r0_norm = infinity_norm(&r0);
        if (z_norm >= (gamma1 - beta)) | (r0_norm >= (gamma2 - beta)) {
            k += u16::try_from(L).unwrap();
            continue;
            // 24: else  ... not needed with 'continue'
        }

        // 25: ⟨⟨c_t_0 ⟩⟩ ← NTT−1 (c_hat ◦ t_hat_0)
        let mut x: [T; K] = [T::zero(); K];
        for (xi, th0i) in x.iter_mut().zip(t_hat_0.iter()) {
            for (xij, (chj, th0ij)) in xi.iter_mut().zip(c_hat.iter().zip(th0i.iter())) {
                *xij = partial_reduce64(i64::from(*chj) * i64::from(*th0ij));
            }
        }
        let c_t_0 = inv_ntt(&x);

        // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)    ▷ Signer’s hint
        let mut mct0 = [R::zero(); K];
        let mut wcc = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                mct0[i][j] = partial_reduce32(Q - c_t_0[i][j]);
                wcc[i][j] = partial_reduce32(w[i][j] - c_s_2[i][j] + c_t_0[i][j]);
                h[i][j] = i32::from(make_hint(gamma2, mct0[i][j], wcc[i][j]));
            }
        }

        // 27: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
        if (infinity_norm(&c_t_0) >= gamma2)
            | (h.iter().flatten().filter(|i| (**i).abs() == 1).count()
                > usize::try_from(omega).unwrap())
        {
            k += u16::try_from(L).unwrap();
            continue;
            // 28: end if
        }
        // 29: end if

        // 30: κ ← κ + ℓ ▷ Increment counter
        // this is done just prior to each of the 'continue' statements above

        // if we made it here, we passed the 'continue' conditions, so have a solution
        break;

        // 31: end while
    }

    // 32: σ ← sigEncode(c_tilde, z mod± q, h)
    let mut zmq: [R; L] = [R::zero(); L];
    for i in 0..L {
        for j in 0..256 {
            zmq[i][j] = center_mod(z[i][j]);
        }
    }
    let sig = sig_encode::<K, L, LAMBDA_DIV4, SIG_LEN>(gamma1, omega, &c_tilde, &zmq, &h)?;

    Ok(sig) // 33: return σ
}


/// Algorithm 3: `ML-DSA.Verify(pk,M,σ)` on page 19.
/// Verifies a signature `σ` for a message `M`. Intuitive flow `result = verify_finish(verify_start())`
///
/// Input: Public key, `pk` ∈ B^{32+32*k*(bitlen(q−1)−d) and message `M` ∈ {0,1}∗. <br>
/// Input: Signature, `σ` ∈ B^{32+ℓ·32·(1+bitlen(γ1−1))+ω+k}. <br>
/// Output: Boolean
pub(crate) fn verify_start<const K: usize, const L: usize, const PK_LEN: usize>(
    pk: &[u8; PK_LEN],
) -> Result<ExpandedPublicKey22<K, L>, &'static str> {
    //
    // 1: (ρ,t_1) ← pkDecode(pk)
    let (rho, t_1): ([u8; 32], [R; K]) = pk_decode(pk)?;

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 6: tr ← H(BytesToBits(pk), 512)
    let mut hasher = h_xof(&[pk]);
    let mut tr = [0u8; 64];
    hasher.read(&mut tr);

    // the last term of:
    // 10: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let t1_hat: [T; K] = ntt(&t_1);
    let mut t1_d2_hat: [T; K] = [T::zero(); K];
    for i in 0..K {
        for j in 0..256 {
            t1_d2_hat[i][j] = partial_reduce64(i64::from(t1_hat[i][j]) * 2i64.pow(D));
        }
    }

    Ok(ExpandedPublicKey22 { cap_a_hat, tr, t1_d2_hat })
}


#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_finish<
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, epk: &ExpandedPublicKey22<K, L>,
    m: &[u8], sig: &[u8; SIG_LEN],
) -> Result<bool, &'static str> {
    //
    let ExpandedPublicKey22 { cap_a_hat, tr, t1_d2_hat } = epk;

    // 1: (ρ,t_1) ← pkDecode(pk)
    // --> calculated in verify_start()

    // 2: (c_tilde, z, h) ← sigDecode(σ)    ▷ Signer’s commitment hash c_tilde, response z and hint h
    let (c_tilde, z, h): ([u8; LAMBDA_DIV4], [R; L], Option<[R; K]>) =
        sig_decode(gamma1, omega, sig)?;

    // 3: if h = ⊥ then return false ▷ Hint was not properly encoded
    if h.is_none() {
        return Ok(false);
        // 4: end if
    };
    let i_norm = infinity_norm(&z);
    ensure!(i_norm < gamma1, "Alg3: i_norm out of range");

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    // --> calculated in verify_start()

    // 6: tr ← H(BytesToBits(pk), 512)
    // --> calculated in verify_start()

    // 7: µ ← H(tr||M,512)    ▷ Compute message representative µ
    let mut hasher = h_xof(&[tr, m]);
    let mut mu = [0u8; 64];
    hasher.read(&mut mu);

    // 8: (c_tilde_1, c_tilde_2) ∈ {0,1}^256 × {0,1}^{2λ-256} ← c_tilde
    let mut c_tilde_1 = [0u8; 32];
    c_tilde_1.copy_from_slice(&c_tilde[0..32]); // c_tilde_2 is just discarded...

    // 9: c ← SampleInBall(c_tilde_1)    ▷ Compute verifier’s challenge from c_tilde
    let c: R = sample_in_ball(tau, &c_tilde_1)?;

    // 10: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let z_hat: [T; L] = ntt(&z);
    let amz_hat: [T; K] = mat_vec_mul(cap_a_hat, &z_hat);

    // NTT(t_1 · 2^d) --> calculated in verify_start()

    let c_hat: T = ntt(&[c])[0];

    let mut cmt_hat: [T; K] = [T::zero(); K];
    for (ntci, ntdi) in cmt_hat.iter_mut().zip(t1_d2_hat.iter()) {
        for (ntcij, (ncj, ntdij)) in ntci.iter_mut().zip(c_hat.iter().zip(ntdi.iter())) {
            *ntcij = partial_reduce64(i64::from(*ncj) * i64::from(*ntdij));
        }
    }

    let mut wp_approx: [R; K] = [R::zero(); K];
    for i in 0..K {
        let mut tmp = T::zero();
        (0..256).for_each(|j| tmp[j] = amz_hat[i][j] - cmt_hat[i][j]);
        wp_approx[i] = inv_ntt(&[tmp])[0];
    }

    // 11: w′_1 ← UseHint(h, w′_Approx)    ▷ Reconstruction of signer’s commitment
    let mut wp_1: [R; K] = [R::zero(); K];
    for i in 0..K {
        for j in 0..256 {
            wp_1[i][j] = use_hint(gamma2, h.ok_or("h scrambled 3")?[i][j], wp_approx[i][j]);
        }
    }

    // 12: c_tilde_′ ← H(µ||w1Encode(w′_1), 2λ)     ▷ Hash it; this should match c_tilde
    let qm12gm1 = (Q - 1) / (2 * gamma2) - 1;
    let bl = bit_length(qm12gm1);
    let t_max = 32 * K * bl;
    let mut tmp = [0u8; 1024]; // TODO: Revisit potential waste of 256 bytes
    w1_encode::<K>(gamma2, &wp_1, &mut tmp[..t_max])?;
    let mut hasher = h_xof(&[&mu, &tmp[..t_max]]);
    let mut c_tilde_p = [0u8; 64];
    hasher.read(&mut c_tilde_p); // leftover to be ignored

    // 13: return [[ ||z||∞ < γ1 −β]] and [[c_tilde = c_tilde_′]] and [[number of 1’s in h is ≤ ω]]
    let left = infinity_norm(&z) < (gamma1 - beta);
    let center = c_tilde[0..LAMBDA_DIV4] == c_tilde_p[0..LAMBDA_DIV4];
    let right = h
        .ok_or("h scrambled 4")?
        .iter()
        .all(|&r| r.iter().filter(|&&e| e == 1).sum::<i32>() <= omega);
    Ok(left & center & right)
}

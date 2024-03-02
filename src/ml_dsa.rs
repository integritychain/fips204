use crate::encodings::{
    pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode,
};
use crate::hashing::{expand_a, expand_mask, expand_s, h_xof, sample_in_ball};
use crate::helpers::{bit_length, ensure, mod_pm, partial_reduce, reduce_q64};
use crate::high_low::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::ntt::{inv_ntt, ntt};
use crate::types::{Zero, R, T};
use crate::{helpers, D, QI, QU};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;


/// Algorithm: 1 `ML-DSA.KeyGen()` on page 15.
/// Generates a public-private key pair.
///
/// Input: `rng` a cryptographically-secure random number generator. <br>
/// Output: Public key, `pk` ∈ B^{32+32k(bitlen(q−1)−d)},
/// and private key, `sk` ∈ `B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}`
pub(crate) fn key_gen<const K: usize, const L: usize, const PK_LEN: usize, const SK_LEN: usize>(
    rng: &mut impl CryptoRngCore, eta: i32,
) -> Result<([u8; PK_LEN], [u8; SK_LEN]), &'static str> {
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

    // 3: cap_a_hat ← ExpandA(ρ)        ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a::<K, L>(&rho);

    // 4: (s_1, s_2 ) ← ExpandS(ρ′)
    let (s_1, s_2): ([R; L], [R; K]) = expand_s::<K, L>(eta, &rho_prime)?;

    // 5: t ← NTT−1 (cap_a_hat ◦ NTT(s_1)) + s_2        ▷ Compute t = As1 + s2
    let s_1_hat = ntt(&s_1);
    let ntt_p1: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &s_1_hat);
    let mut t = inv_ntt(&ntt_p1);
    t = helpers::vec_add(&t, &s_2);

    // 6: (t_1 , t_0 ) ← Power2Round(t, d)              ▷ Compress t
    let mut t_1: [R; K] = [R::zero(); K];
    let mut t_0: [R; K] = [R::zero(); K];
    for l in 0..K {
        for m in 0..256 {
            (t_1[l][m], t_0[l][m]) = power2round(t[l][m]);
        }
    }

    // 7: pk ← pkEncode(ρ, t_1)
    let pk: [u8; PK_LEN] = pk_encode::<K, PK_LEN>(&rho, &t_1)?;

    // 8: tr ← H(BytesToBits(pk), 512)
    let mut tr = [0u8; 64];
    let mut h = h_xof(&[&pk]);
    h.read(&mut tr);

    // 9: sk ← skEncode(ρ, K, tr, s_1 , s_2 , t_0 )     ▷ K and tr are for use in signing
    let sk: [u8; SK_LEN] = sk_encode::<K, L, SK_LEN>(eta, &rho, &cap_k, &tr, &s_1, &s_2, &t_0)?;

    // 10: return (pk, sk)
    Ok((pk, sk))
}


/// Algorithm 2 ML-DSA.Sign(sk, M) on page 17
/// Generates a signature for a message M.
///
/// Input: Private key, `sk` ∈ `B^{32+32+64+32·((ℓ+k)·bitlen(2η)+dk)}` and the message `M` ∈ {0,1}^∗ <br>
/// Output: Signature, `σ` ∈ `B^{32+ℓ·32·(1+bitlen(gamma_1 −1))+ω+k}`
#[allow(clippy::similar_names)]
#[allow(clippy::many_single_char_names)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign<
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
>(
    rand_gen: &mut impl CryptoRngCore, beta: i32, eta: i32, gamma1: i32, gamma2: i32, omega: i32,
    tau: i32, sk: &[u8; SK_LEN], message: &[u8],
) -> Result<[u8; SIG_LEN], &'static str> {
    // 1:  (ρ, K, tr, s_1 , s_2 , t_0 ) ← skDecode(sk)
    #[allow(clippy::type_complexity)]
    let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode::<K, L, SK_LEN>(eta, sk)?;

    // 2:  s_hat_1 ← NTT(s_1)
    let s_hat_1 = ntt(&s_1);

    // 3:  s_hat_2 ← NTT(s_2)
    let s_hat_2 = ntt(&s_2);

    // 4:  t_hat_0 ← NTT(t_0)
    let t_hat_0 = ntt(&t_0);

    // 5:  cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 6:  µ ← H(tr||M, 512)    ▷ Compute message representative µ
    let mut h = h_xof(&[&tr, message]);
    let mut mu = [0u8; 64];
    h.read(&mut mu);

    // 7:  rnd ← {0,1}^256    ▷ For the optional deterministic variant, substitute rnd ← {0}256
    let mut rnd = [0u8; 32];
    rand_gen.try_fill_bytes(&mut rnd).map_err(|_| "Alg 2: rng fail")?;

    // 8:  ρ′ ← H(K||rnd||µ, 512)    ▷ Compute private random seed
    let mut h = h_xof(&[&cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h.read(&mut rho_prime);

    // 9:  κ ← 0    ▷ Initialize counter κ
    let mut k = 0u16;

    // 10: (z, h) ← ⊥
    let (mut z, mut h) = ([R::zero(); L], [R::zero(); K]); // z & h are raw values;
    let mut c_tilde = [0u8; 2 * 256 / 8]; //[0u8; 2 * LAMBDA / 8];
                                          // 11: while (z, h) = ⊥ do          ▷ Rejection sampling loop
                                          // rather than setting (z, h) = ⊥, we just do a loop with continues where needed
    loop {
        //
        // 12: y ← ExpandMask(ρ′ , κ)
        let y: [R; L] = expand_mask::<L>(gamma1, &rho_prime, k)?;

        // 13: w ← NTT−1 (cap_a_hat ◦ NTT(y))
        let ntt_y = ntt(&y);
        let ntt_p1: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &ntt_y);
        let w = inv_ntt(&ntt_p1);

        // 14: w_1 ← HighBits(w)            ▷ Signer’s commitment
        let mut w_1: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                w_1[i][j] = high_bits(gamma2, w[i][j]);
            }
        }

        // 15: c_tilde ∈ {0,1}^{2Lambda} ← H(µ || w1Encode(w_1), 2Lambda)     ▷ Commitment hash
        let w1e_len = 32 * K * bit_length((QI - 1) / (2 * gamma2) - 1);
        let mut w1_tilde = [0u8; 1024];
        w1_encode::<K>(gamma2, &w_1, &mut w1_tilde[0..w1e_len])?;
        let mut h99 = h_xof(&[&mu, &w1_tilde[0..w1e_len]]);
        h99.read(&mut c_tilde); // Ok to read a bit too much

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
                *xij = reduce_q64(*chj as i64 * *sh1ij as i64);
            }
        }
        let c_s_1 = inv_ntt(&x);

        // 20: ⟨⟨c_s_2 ⟩⟩ ← NTT−1 (c_hat ◦ s_hat_2)
        let mut x: [T; K] = [T::zero(); K];
        for (xi, sh2i) in x.iter_mut().zip(s_hat_2.iter()) {
            for (xij, (chj, sh2ij)) in xi.iter_mut().zip(c_hat.iter().zip(sh2i.iter())) {
                *xij = reduce_q64(*chj as i64 * *sh2ij as i64);
            }
        }
        let c_s_2 = inv_ntt(&x);

        // 21: z ← y + ⟨⟨c_s_1⟩⟩    ▷ Signer’s response
        for i in 0..L {
            for j in 0..256 {
                z[i][j] = partial_reduce(y[i][j] + c_s_1[i][j]);
            }
        }

        // 22: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let mut r0: [R; K] = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                r0[i][j] = low_bits(gamma2, partial_reduce(w[i][j] - c_s_2[i][j]));
            }
        }

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥    ▷ Validity checks
        let z_norm = helpers::infinity_norm(&z);
        let r0_norm = helpers::infinity_norm(&r0);
        if (z_norm >= (gamma1 - beta)) | (r0_norm >= (gamma2 - beta)) {
            k += u16::try_from(L).unwrap();
            continue;
            // 24: else  ... not really needed, with 'continue' above
        }
        // 25: ⟨⟨c_t_0 ⟩⟩ ← NTT−1 (c_hat ◦ t_hat_0)
        let mut x: [T; K] = [T::zero(); K];
        for (xi, th0i) in x.iter_mut().zip(t_hat_0.iter()) {
            for (xij, (chj, th0ij)) in xi.iter_mut().zip(c_hat.iter().zip(th0i.iter())) {
                *xij = reduce_q64(*chj as i64 * *th0ij as i64);
            }
        }
        let c_t_0 = inv_ntt(&x);

        // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)    ▷ Signer’s hint
        let mut mct0 = [R::zero(); K];
        let mut wcc = [R::zero(); K];
        for i in 0..K {
            for j in 0..256 {
                mct0[i][j] = partial_reduce(QI - c_t_0[i][j]);
                wcc[i][j] = partial_reduce(w[i][j] - c_s_2[i][j] + c_t_0[i][j]);
                h[i][j] = make_hint(gamma2, mct0[i][j], wcc[i][j]) as i32;
            }
        }

        // 27: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
        if (helpers::infinity_norm(&c_t_0) >= gamma2)
            | (h.iter().flatten().filter(|i| (**i).abs() == 1).count() > usize::try_from(omega).unwrap())
        {
            k += u16::try_from(L).unwrap();
            continue;
            // 28: end if
        }
        // 29: end if
        //
        // 30: κ ← κ + ℓ ▷ Increment counter
        // if we made it here, we passed the 'continue' conditions, so have a solution
        break;
        // 31: end while
    }
    //
    // 32: σ ← sigEncode(c_tilde, z mod± q, h)
    let mut zmq: [R; L] = [R::zero(); L];
    for i in 0..L {
        for j in 0..256 {
            zmq[i][j] = mod_pm(z[i][j], QU);
        }
    }
    let sig = sig_encode::<K, L, LAMBDA_DIV4, SIG_LEN>(
        gamma1,
        omega,
        &(c_tilde[0..LAMBDA_DIV4].try_into().unwrap()),
        &zmq,
        &h,
    )?;

    Ok(sig) // 33: return σ
}


/// Algorithm 3: `ML-DSA.Verify(pk, M, σ)` on page 19.
/// Verifies a signature `σ` for a message `M`.
///
/// Input: Public key, `pk` ∈ B^{32 + 32*k*(bitlen(q−1) − d) and message `M` ∈ {0,1}∗. <br>
/// Input: Signature, `σ` ∈ B^{32 + ℓ·32·(1 + bitlen(γ1−1)) + ω + k}. <br>
/// Output: Boolean
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify<
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, pk: &[u8; PK_LEN], m: &[u8],
    sig: &[u8; SIG_LEN],
) -> Result<bool, &'static str> {
    // 1: (ρ,t_1) ← pkDecode(pk)
    let (rho, t_1): ([u8; 32], [R; K]) = pk_decode::<K, PK_LEN>(pk)?;

    // 2: (c_tilde, z, h) ← sigDecode(σ)    ▷ Signer’s commitment hash c_tilde, response z and hint h
    let (c_tilde, z, h) = //: (Vec<u8>, [R; L], Option<[R; K]>) =
        sig_decode::<K, L, LAMBDA_DIV4>(gamma1, omega, sig)?;

    // 3: if h = ⊥ then return false ▷ Hint was not properly encoded
    if h.is_none() {
        return Ok(false);
    };
    let i_norm = helpers::infinity_norm(&z);
    ensure!(i_norm < gamma1, "Algorithm3: i_norm out of range");
    // 4: end if

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    let cap_a_hat: [[T; L]; K] = expand_a(&rho);

    // 6: tr ← H(BytesToBits(pk), 512)
    let mut hasher = h_xof(&[pk]);
    let mut tr = [0u8; 64];
    hasher.read(&mut tr);

    // 7: µ ← H(tr||M,512)    ▷ Compute message representative µ
    let mut hasher = h_xof(&[&tr, m]);
    let mut mu = [0u8; 64];
    hasher.read(&mut mu);

    // 8: (c_tilde_1, c_tilde_2) ∈ {0,1}^256 × {0,1}^{2λ-256} ← c_tilde   NOTE: c_tilde_2 is discarded
    let c_tilde_1 = c_tilde; //.clone(); // c_tilde_2 is just discarded...

    // 9: c ← SampleInBall(c_tilde_1)    ▷ Compute verifier’s challenge from c_tilde
    let c: R =
        sample_in_ball(tau, &c_tilde_1[0..32].try_into().map_err(|_e| "c_tilde_1 scrambled")?)?;

    // 10: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let ntt_z = ntt(&z);
    let ntt_a_z: [T; K] = helpers::mat_vec_mul(&cap_a_hat, &ntt_z);

    let ntt_t1 = ntt(&t_1);
    let mut ntt_t1_d2: [T; K] = [T::zero(); K];
    for i in 0..K {
        for j in 0..256 {
            ntt_t1_d2[i][j] = reduce_q64(ntt_t1[i][j] as i64 * 2i32.pow(D) as i64);
        }
    }

    let ntt_c = ntt(&[c])[0];

    let mut ntt_ct: [T; K] = [T::zero(); K];
    for (ntci, ntdi) in ntt_ct.iter_mut().zip(ntt_t1_d2.iter()) {
        for (ntcij, (ncj, ntdij)) in ntci.iter_mut().zip(ntt_c.iter().zip(ntdi.iter())) {
            *ntcij = reduce_q64(*ncj as i64 * *ntdij as i64);
        }
    }

    let mut wp_approx: [R; K] = [R::zero(); K];
    for i in 0..K {
        let mut tmp = T::zero();
        (0..256).for_each(|j| tmp[j] = ntt_a_z[i][j] - ntt_ct[i][j]);
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
    let qm12gm1 = (QI - 1) / (2 * gamma2) - 1;
    let bl = bit_length(qm12gm1);
    let t_max = 32 * K * bl;
    let mut tmp = [0u8; 1024]; // TODO: optimize to [0u8; 32 * K * bl]
    w1_encode::<K>(gamma2, &wp_1, &mut tmp[..t_max])?;
    let mut hasher = h_xof(&[&mu, &tmp[..t_max]]);
    let mut c_tilde_p = [0u8; 64];
    hasher.read(&mut c_tilde_p); // leftover to be ignored

    // 13: return [[ ||z||∞ < γ1 −β]] and [[c_tilde = c_tilde_′]] and [[number of 1’s in h is ≤ ω]]
    let left = helpers::infinity_norm(&z) < (gamma1 - beta);
    let center = c_tilde[0..LAMBDA_DIV4] == c_tilde_p[0..LAMBDA_DIV4];
    let right = h // TODO: confirm -- this checks #h per each R (rather than overall total)
        .ok_or("h scrambled 4")?
        .iter()
        .all(|&r| r.iter().filter(|&&e| e == 1).sum::<i32>() <= omega);
    Ok(left & center & right)
}

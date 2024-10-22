// This file implements functionality from FIPS 204 sections 5/6: Key Generation, Signing, Verification

use crate::encodings::{pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, w1_encode};
use crate::hashing::{expand_a, expand_mask, expand_s, h256_xof, sample_in_ball};
use crate::helpers::{
    add_vector_ntt, center_mod, full_reduce32, infinity_norm, mat_vec_mul, mont_reduce,
    partial_reduce32, to_mont,
};
use crate::high_low::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::ntt::{inv_ntt, ntt};
use crate::types::{PrivateKey, PublicKey, R, T};
use crate::{D, Q};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;


/// Algorithm: 1 `ML-DSA.KeyGen()` on page 15.
/// Generates a public-private key pair.
///
/// **Input**: `rng` a cryptographically-secure random number generator. <br>
/// **Output**: Public key, `pk ∈ B^{32+32·k·(bitlen(q−1)−d)}`, and
///             private key, `sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2·η)+d·k)}`
///
/// # Errors
/// Returns an error when the random number generator fails.
pub(crate) fn key_gen<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    rng: &mut impl CryptoRngCore, eta: i32,
) -> Result<(PublicKey<K, L>, PrivateKey<K, L>), &'static str> {
    //
    // 1: ξ ← {0,1}^{256}    ▷ Choose random seed
    let mut xi = [0u8; 32];
    rng.try_fill_bytes(&mut xi).map_err(|_| "Random number generator failed")?;

    Ok(key_gen_internal::<CTEST, K, L, PK_LEN, SK_LEN>(eta, &xi))
}


// The following two functions effectively implement A) Algorithm 2 ML-DSA.Sign(sk, M) on
// page 17 and B) Algorithm 7 ML-DSA.Sign_internal(sk, M', rnd) on page 25 in conjunction
// with the top level try_sign* API in lib.rs. This is due to the support for a precomputed
// private key that is able to sign with higher performance.


/// Continuation of `sign_start()`
#[allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(crate) fn sign<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
    const W1_LEN: usize,
>(
    rand_gen: &mut impl CryptoRngCore, beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32,
    esk: &PrivateKey<K, L>, message: &[u8], ctx: &[u8], oid: &[u8], phm: &[u8], nist: bool,
) -> Result<[u8; SIG_LEN], &'static str> {
    //
    // 1: (ρ, K, tr, s_1, s_2, t_0) ← skDecode(sk)
    // --> calculated in expand_private()
    //
    // 2: s_hat_1 ← NTT(s_1)
    // --> calculated in expand_private()
    //
    // 3: s_hat_2 ← NTT(s_2)
    // --> calculated in expand_private()
    //
    // 4: t_hat_0 ← NTT(t_0)
    // --> calculated in expand_private()
    //
    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    // --> calculated in expand_private()

    // Extract from expand_private()
    let PrivateKey {
        rho,
        cap_k,
        tr,
        s_hat_1_mont,
        s_hat_2_mont,
        t_hat_0_mont,
        //cap_a_hat,
    } = esk;

    let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(rho);

    // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 , 64)    ▷ Compute message representative µ
    // We may have arrived from 3 different paths
    let mut h6 = if nist {
        // 1. NIST vectors are being applied to "internal" functions
        h256_xof(&[tr, message])
    } else if oid.is_empty() {
        // 2. From ML-DSA.Sign():  𝑀′ ← BytesToBits(IntegerToBytes(0,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        h256_xof(&[tr, &[0u8], &[ctx.len().to_le_bytes()[0]], ctx, message])
    } else {
        // 3. From HashML-DSA.Sign(): 𝑀′ ← BytesToBits(IntegerToBytes(1,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
        h256_xof(&[tr, &[1u8], &[oid.len().to_le_bytes()[0]], ctx, oid, phm])
    };
    let mut mu = [0u8; 64];
    h6.read(&mut mu);

    // rnd ← {0,1}^256    ▷ For the optional deterministic variant, substitute rnd ← {0}^256
    let mut rnd = [0u8; 32];
    rand_gen.try_fill_bytes(&mut rnd).map_err(|_| "Alg 2: rng fail")?;

    // 7: ρ′ ← H(K || rnd || µ, 512)    ▷ Compute private random seed
    let mut h8 = h256_xof(&[cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h8.read(&mut rho_prime);

    // 8: κ ← 0    ▷ Initialize counter κ
    let mut kappa_ctr = 0u16;

    // 9: (z, h) ← ⊥    ▷ we will handle ⊥ inline with 'continue'
    let mut z: [R; L];
    let mut h: [R; K];
    let mut c_tilde = [0u8; LAMBDA_DIV4]; // size could be fixed at 32; but spec will fix flaw

    // 10: while (z, h) = ⊥ do    ▷ Rejection sampling loop (with continue for ⊥)
    loop {
        //
        // 11: y ← ExpandMask(ρ′, κ)
        let y: [R; L] = expand_mask(gamma1, &rho_prime, kappa_ctr);

        // 12: w ← NTT−1(cap_a_hat ◦ NTT(y))
        let w: [R; K] = {
            let y_hat: [T; L] = ntt(&y);
            let ay_hat: [T; K] = mat_vec_mul(&cap_a_hat, &y_hat);
            inv_ntt(&ay_hat)
        };

        // 13: w_1 ← HighBits(w)    ▷ Signer’s commitment
        let w_1: [R; K] =
            core::array::from_fn(|k| R(core::array::from_fn(|n| high_bits(gamma2, w[k].0[n]))));

        // There is effectively no step 14 due to formatting error in spec

        // 15: c_tilde ∈ {0,1}^{2·Lambda} ← H(µ || w1Encode(w_1), 2·Lambda)     ▷ Commitment hash
        let mut w1_tilde = [0u8; W1_LEN];
        w1_encode::<K>(gamma2, &w_1, &mut w1_tilde);
        let mut h15 = h256_xof(&[&mu, &w1_tilde]);
        h15.read(&mut c_tilde);

        // 16: c ← SampleInBall(c_tilde_1)    ▷ Verifier’s challenge
        let c: R = sample_in_ball::<CTEST>(tau, &c_tilde);

        // 17: c_hat ← NTT(c)
        let c_hat: &T = &ntt(&[c])[0];

        // 18: ⟨⟨c_s_1⟩⟩ ← NTT−1(c_hat ◦ s_hat_1)
        let c_s_1: [R; L] = {
            let cs1_hat: [T; L] = core::array::from_fn(|l| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(s_hat_1_mont[l].0[n]))
                }))
            });
            inv_ntt(&cs1_hat)
        };

        // 19: ⟨⟨c_s_2⟩⟩ ← NTT−1(c_hat ◦ s_hat_2)
        let c_s_2: [R; K] = {
            let cs2_hat: [T; K] = core::array::from_fn(|k| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(s_hat_2_mont[k].0[n]))
                }))
            });
            inv_ntt(&cs2_hat)
        };

        // 20: z ← y + ⟨⟨c_s_1⟩⟩    ▷ Signer’s response
        z = core::array::from_fn(|l| {
            R(core::array::from_fn(|n| partial_reduce32(y[l].0[n] + c_s_1[l].0[n])))
        });

        // 21: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let r0: [R; K] = core::array::from_fn(|k| {
            R(core::array::from_fn(|n| {
                low_bits(gamma2, partial_reduce32(w[k].0[n] - c_s_2[k].0[n]))
            }))
        });

        // There is effectively no step 22 due to formatting error in spec

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥    ▷ Validity checks
        let z_norm = infinity_norm(&z);
        let r0_norm = infinity_norm(&r0);
        // CTEST is used only for constant-time measurements via `dudect`
        if !CTEST && ((z_norm >= (gamma1 - beta)) || (r0_norm >= (gamma2 - beta))) {
            kappa_ctr += u16::try_from(L).expect("cannot fail");
            continue;
            //
            // 24: else  ... not needed with 'continue'
        }

        // 25: ⟨⟨c_t_0⟩⟩ ← NTT−1(c_hat ◦ t_hat_0)
        let c_t_0: [R; K] = {
            let ct0_hat: [T; K] = core::array::from_fn(|k| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(t_hat_0_mont[k].0[n]))
                }))
            });
            inv_ntt(&ct0_hat)
        };

        // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)    ▷ Signer’s hint
        h = core::array::from_fn(|k| {
            R(core::array::from_fn(|n| {
                i32::from(make_hint(
                    gamma2,
                    Q - c_t_0[k].0[n], // no reduce
                    partial_reduce32(w[k].0[n] - c_s_2[k].0[n] + c_t_0[k].0[n]),
                ))
            }))
        });

        // There is effectively no step 22 due to formatting error in spec

        // 28: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
        // CTEST is used only for constant-time measurements via `dudect`
        if !CTEST
            && ((infinity_norm(&c_t_0) >= gamma2)
                || (h.iter().map(|h_i| h_i.0.iter().sum::<i32>()).sum::<i32>() > omega))
        {
            kappa_ctr += u16::try_from(L).expect("cannot fail");
            continue;
            // 29: end if
        }

        // 30: end if  (not needed as ⊥-related logic uses continue

        // 31: κ ← κ + ℓ ▷ Increment counter
        // this is done just prior to each of the 'continue' statements above

        // if we made it here, we passed the 'continue' conditions, so have a solution
        break;

        // 32: end while
    }

    // 33: σ ← sigEncode(c_tilde, z mod± q, h)
    let zmodq: [R; L] =
        core::array::from_fn(|l| R(core::array::from_fn(|n| center_mod(z[l].0[n]))));
    let sig = sig_encode::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN>(gamma1, omega, &c_tilde, &zmodq, &h);

    // 34: return σ
    Ok(sig)
}


/// Continuation of `verify_start()`. The `lib.rs` wrapper around this will convert `Error()` to false.
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub(crate) fn verify<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
    const W1_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, epk: &PublicKey<K, L>, m: &[u8],
    sig: &[u8; SIG_LEN], ctx: &[u8], oid: &[u8], phm: &[u8], nist: bool,
) -> Result<bool, &'static str> {
    //
    //let PublicKey { rho: _, cap_a_hat, tr, t1_d2_hat_mont } = epk;
    let PublicKey { rho, tr, t1_d2_hat_mont } = epk;

    // 1: (ρ, t_1) ← pkDecode(pk)
    // --> calculated in expand_public()

    // 2: (c_tilde, z, h) ← sigDecode(σ)    ▷ Signer’s commitment hash c_tilde, response z and hint h
    let (c_tilde, z, h): ([u8; LAMBDA_DIV4], [R; L], Option<[R; K]>) =
        sig_decode(gamma1, omega, sig)?;

    // 3: if h = ⊥ then return false ▷ Hint was not properly encoded
    if h.is_none() {
        return Ok(false);

        // 4: end if
    };
    let h = h.unwrap();
    debug_assert!(infinity_norm(&z) <= gamma1, "Alg 3: i_norm out of range"); // TODO: consider revising

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    // --> calculated in expand_public()

    // 6: tr ← H(pk, 64)
    // --> calculated in expand_public()

    // 7: 𝜇 ← (H(BytesToBits(tr)||𝑀′, 64))    ▷ Compute message representative µ
    // We may have arrived from 3 different paths
    let mut h7 = if nist {
        // 1. NIST vectors are being applied to "internal" functions
        h256_xof(&[tr, m])
    } else if oid.is_empty() {
        // 2. From ML-DSA.Verify(): 5: 𝑀′ ← BytesToBits(IntegerToBytes(0,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        h256_xof(&[tr, &[0u8], &[ctx.len().to_le_bytes()[0]], ctx, m])
    } else {
        // 3. From HashML-DSA.Verify(): 18: 𝑀′ ← BytesToBits(IntegerToBytes(1,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
        h256_xof(&[tr, &[1u8], &[oid.len().to_le_bytes()[0]], ctx, oid, phm])
    };
    let mut mu = [0u8; 64];
    h7.read(&mut mu);

    // 8: c ← SampleInBall(c_tilde_1)    ▷ Compute verifier’s challenge from c_tilde
    let c: R = sample_in_ball::<false>(tau, &c_tilde); // false, as this instance isn't pertinent to CT

    // 9: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let wp_approx: [R; K] = {
        // hardcode CTEST as false since everything is public here
        let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(rho);
        let z_hat: [T; L] = ntt(&z);
        let az_hat: [T; K] = mat_vec_mul(&cap_a_hat, &z_hat);
        // NTT(t_1 · 2^d) --> calculated in expand_public()
        let c_hat: &T = &ntt(&[c])[0];
        inv_ntt(&core::array::from_fn(|k| {
            T(core::array::from_fn(|n| {
                az_hat[k].0[n]
                    - mont_reduce(i64::from(c_hat.0[n]) * i64::from(t1_d2_hat_mont[k].0[n]))
            }))
        }))
    };

    // 10: w′_1 ← UseHint(h, w′_Approx)    ▷ Reconstruction of signer’s commitment
    let wp_1: [R; K] = core::array::from_fn(|k| {
        R(core::array::from_fn(|n| use_hint(gamma2, h[k].0[n], wp_approx[k].0[n])))
    });

    // There is effectively no step 11 due to formatting error in spec

    // 12: c_tilde_′ ← H(µ || w1Encode(w′_1), 2λ)     ▷ Hash it; this should match c_tilde
    let mut tmp = [0u8; W1_LEN];
    w1_encode::<K>(gamma2, &wp_1, &mut tmp);
    let mut h12 = h256_xof(&[&mu, &tmp]);
    let mut c_tilde_p = [0u8; LAMBDA_DIV4];
    h12.read(&mut c_tilde_p); // leftover to be ignored

    // 13: return [[ ||z||∞ < γ1 −β]] and [[c_tilde = c_tilde_′]] and [[number of 1’s in h is ≤ ω]]
    let left = infinity_norm(&z) < (gamma1 - beta);
    let center = c_tilde == c_tilde_p; // verify not CT
    let right = h.iter().all(|r| r.0.iter().filter(|&&e| e == 1).sum::<i32>() <= omega);
    Ok(left && center && right)
}


/// Algorithm: 6 `ML-DSA.KeyGen_internal()` on page 15.
/// Generates a public-private key pair.
///
/// **Input**: `rng` a cryptographically-secure random number generator. <br>
/// **Output**: Public key, `pk ∈ B^{32+32·k·(bitlen(q−1)−d)}`, and
///             private key, `sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2·η)+d·k)}`
///
/// # Errors
/// Returns an error when the random number generator fails.
pub(crate) fn key_gen_internal<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    eta: i32, xi: &[u8; 32],
) -> (PublicKey<K, L>, PrivateKey<K, L>) {
    //
    // 1: (rho, rho′, 𝐾) ∈ 𝔹32 × 𝔹64 × 𝔹32 ← H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
    let mut h2 = h256_xof(&[xi, &[K.to_le_bytes()[0]], &[L.to_le_bytes()[0]]]);
    let mut rho = [0u8; 32];
    h2.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    h2.read(&mut rho_prime);
    let mut cap_k = [0u8; 32];
    h2.read(&mut cap_k);

    // There is effectively no step 2 due to formatting error in spec

    // 4: (s_1, s_2) ← ExpandS(ρ′)
    let (s_1, s_2): ([R; L], [R; K]) = expand_s::<CTEST, K, L>(eta, &rho_prime);

    // 3: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    // 5: t ← NTT−1(cap_a_hat ◦ NTT(s_1)) + s_2    ▷ Compute t = As1 + s2
    // 6: (t_1, t_0) ← Power2Round(t, d)    ▷ Compress t

    let (t_1, t_0): ([R; K], [R; K]) = {
        let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(&rho);
        let s_1_hat: [T; L] = ntt(&s_1);
        let as1_hat: [T; K] = mat_vec_mul(&cap_a_hat, &s_1_hat);
        let t_not_reduced: [R; K] = add_vector_ntt(&inv_ntt(&as1_hat), &s_2);
        let t: [R; K] =
            core::array::from_fn(|k| R(core::array::from_fn(|n| full_reduce32(t_not_reduced[k].0[n]))));
        power2round(&t)
    };

    // There is effectively no step 7 due to formatting error in spec

    // 8: pk ← pkEncode(ρ, t_1)
    let pk: [u8; PK_LEN] = pk_encode(&rho, &t_1);

    // 9: tr ← H(BytesToBits(pk), 512)
    let mut tr = [0u8; 64];
    let mut h8 = h256_xof(&[&pk]);
    h8.read(&mut tr);

    // 10: sk ← skEncode(ρ, K, tr, s_1, s_2, t_0)     ▷ K and tr are for use in signing
    //let sk: [u8; SK_LEN] = sk_encode(eta, &rho, &cap_k, &tr, &s_1, &s_2, &t_0);

    // the last term of:
    // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
    let t1_hat_mont: [T; K] = to_mont(&ntt(&t_1));
    let t1_d2_hat_mont: [T; K] = to_mont(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D)))
    }));
    //let pk = PublicKey { rho, cap_a_hat: cap_a_hat.clone(), tr, t1_d2_hat_mont };
    let pk = PublicKey { rho, tr, t1_d2_hat_mont };

    // 2: s_hat_1 ← NTT(s_1)
    //let s_hat_1_mont: [T; L] = to_mont(&s_1_hat); //ntt(&s_1));
    let s_hat_1_mont: [T; L] = to_mont(&ntt(&s_1));
                                                  // 3: s_hat_2 ← NTT(s_2)
    let s_hat_2_mont: [T; K] = to_mont(&ntt(&s_2));
    // 4: t_hat_0 ← NTT(t_0)
    let t_hat_0_mont: [T; K] = to_mont(&ntt(&t_0));
    let sk = PrivateKey {
        rho,
        cap_k,
        tr,
        s_hat_1_mont,
        s_hat_2_mont,
        t_hat_0_mont,
        // cap_a_hat,
    };

    // 11: return (pk, sk)
    (pk, sk)
}


/// Expand the private/secret key by pre-calculating some constants used in the signing process.
/// This is only used in the `try_from_bytes()` deserialization functionality.
/// # Errors
/// Returns an error on malformed private key.
pub(crate) fn expand_private<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const SK_LEN: usize,
>(
    eta: i32, sk: &[u8; SK_LEN],
) -> Result<PrivateKey<K, L>, &'static str> {
    //
    // 1: (ρ, K, tr, s_1, s_2, t_0) ← skDecode(sk)
    let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode(eta, sk)?;

    // 2: s_hat_1 ← NTT(s_1)
    let s_hat_1_mont: [T; L] = to_mont(&ntt(&s_1));

    // 3: s_hat_2 ← NTT(s_2)
    let s_hat_2_mont: [T; K] = to_mont(&ntt(&s_2));

    // 4: t_hat_0 ← NTT(t_0)
    let t_hat_0_mont: [T; K] = to_mont(&ntt(&t_0));

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    //let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(rho);

    Ok(PrivateKey {
        rho: *rho,
        cap_k: *cap_k,
        tr: *tr,
        s_hat_1_mont,
        s_hat_2_mont,
        t_hat_0_mont,
        //cap_a_hat,
    })
}


/// Expand the public key by pre-calculating some constants used in the signing process.
/// This is only used in the `try_from_bytes()` deserialization functionality.
/// # Errors
/// Returns an error on malformed public key.
pub(crate) fn expand_public<const K: usize, const L: usize, const PK_LEN: usize>(
    pk: &[u8; PK_LEN],
) -> Result<PublicKey<K, L>, &'static str> {
    //
    // 1: (ρ,t_1) ← pkDecode(pk)
    let (rho, t_1): (&[u8; 32], [R; K]) = pk_decode(pk)?;

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    //let cap_a_hat: [[T; L]; K] = expand_a::<false, K, L>(rho);

    // 6: tr ← H(pk, 64)
    let mut h6 = h256_xof(&[pk]);
    let mut tr = [0u8; 64];
    h6.read(&mut tr);

    // the last term of:
    // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
    let t1_hat_mont: [T; K] = to_mont(&ntt(&t_1));
    let t1_d2_hat_mont: [T; K] = to_mont(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D)))
    }));

    //Ok(PublicKey { rho: *rho, cap_a_hat, tr, t1_d2_hat_mont })
    Ok(PublicKey { rho: *rho, tr, t1_d2_hat_mont })
}

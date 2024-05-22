use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use fips204::traits::{KeyGen, SerDes, Signer};
use rand_core::{CryptoRng, RngCore};
use fips204::ml_dsa_44::PrivateKey;

// Test RNG to regurgitate incremented values when 'asked'
#[repr(align(8))]
#[derive(Clone)]
struct TestRng {
    value: u8,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.iter_mut().for_each(|b| *b = self.value);
        //self.value = self.value.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for TestRng {}


// TODO: note to self. goal is to show timing is independent of secret key, not randomness nor message.
// so rnd gen could be kept constant

fn sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 1024;
    const ITERATIONS_OUTER: usize = 1024;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let mut rng_right = TestRng {value: 12};
    //let (_pk1, sk_right) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng_right).unwrap();  // Generate both public and secret keys
    //let esk_right = ml_dsa_44::KG::gen_expanded_private_vt(&sk_right).unwrap();
    let mut rng_left = TestRng {value: 56};
    //let (_pk2, sk_left) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng_left).unwrap();  // Generate both public and secret keys
    //let esk_left = ml_dsa_44::KG::gen_expanded_private_vt(&sk_left).unwrap();

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut refs: [(TestRng, PrivateKey); ITERATIONS_OUTER] = core::array::from_fn(|_| {
        let (_pk1, sk_right) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng_right).unwrap();
        (TestRng {value: 12}, sk_right)
    });

    // Interleave left and right
    for i in (0..ITERATIONS_OUTER).step_by(2) {
        classes[i] = Class::Left;
        let (_pk2, sk_left) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng_left).unwrap();
        refs[i] = (TestRng {value: 56}, sk_left);
    }

    for (class, sk) in classes.into_iter().zip(refs.into_iter()) {
        runner.run_one(class, || {
            let mut rng = sk.0.clone();
            for _ in 0..ITERATIONS_INNER {
                let _ = ml_dsa_44::dudect_keygen_sign_with_rng(&mut rng, &message);
                //let (_pk, skX) = ml_dsa_44::try_keygen_with_rng_vt(&mut rng).unwrap();
                //let _ = ml_dsa_44::KG::gen_expanded_private_vt(&sk).unwrap();  // ONLY DOES SIGN START
                //let _ = skX.try_sign_with_rng_ct(&mut rng, &message);
            }
        })
    }
}

ctbench_main!(sign);

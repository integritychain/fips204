use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use fips204::traits::{KeyGen, Signer};
use rand_core::{CryptoRng, RngCore};

// Test RNG to regurgitate incremented values when 'asked'
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
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];  // TODO: consider whether this should be left/right (no)

    let (_pk1, sk_right) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys
    let esk_right = ml_dsa_44::KG::gen_expanded_private_vt(&sk_right).unwrap();
    let (_pk2, sk_left) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys
    let esk_left = ml_dsa_44::KG::gen_expanded_private_vt(&sk_left).unwrap();

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut refs = [(12, &esk_right); ITERATIONS_OUTER];  // 12 = rng seed

    // Interleave left and right
    for i in (0..(ITERATIONS_OUTER)).step_by(2) {
        classes[i] = Class::Left;
        //refs[i] = (12, &esk_left);  // 12 = rng seed
    }

    for (class, tuple) in classes.into_iter().zip(refs.into_iter()) {
        runner.run_one(class, || {
            let mut rng = TestRng {value: tuple.0};
            for _ in 0..ITERATIONS_INNER {
                let _ = tuple.1.try_sign_with_rng_ct(&mut rng, &message);
            }
        })
    }
}

ctbench_main!(sign);

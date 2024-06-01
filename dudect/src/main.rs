use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use rand_core::{CryptoRng, RngCore};

// Test RNG to regurgitate incremented values when 'asked'
#[derive(Clone)]
#[repr(align(8))]
struct TestRng { value: u32 }

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.iter_mut().for_each(|b| *b = self.value.to_le_bytes()[0]);
        out[0..4].copy_from_slice(&self.value.to_be_bytes());
        self.value = self.value.wrapping_add(1);
        Ok(())
    }
}

impl CryptoRng for TestRng {}



fn keygen_and_sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 200_000;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let mut classes = [Class::Right; ITERATIONS_OUTER];
    let mut rngs: [TestRng; ITERATIONS_OUTER] = core::array::from_fn(|_| TestRng {value: 12});

    // Interleave left and right
    for i in (0..ITERATIONS_OUTER).step_by(2) {
        classes[i] = Class::Left;
        rngs[i] = TestRng {value: 56}; // <--- different seed value
    }

    for (class, rng) in classes.into_iter().zip(rngs.into_iter()) {
        runner.run_one(class, || {
            let mut rng = rng.clone();
            for _ in 0..ITERATIONS_INNER {
                let _ = ml_dsa_44::dudect_keygen_sign_with_rng(&mut rng, &message).unwrap();
            }
        })
    }
}

ctbench_main!(keygen_and_sign);

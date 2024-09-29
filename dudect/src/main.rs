use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use rand_core::{CryptoRng, RngCore};

// Simplistic RNG to regurgitate set value
#[derive(Clone)]
#[repr(align(8))]
struct TestRng([u8; 32]);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.copy_from_slice(&self.0);
        Ok(())
    }
}

impl CryptoRng for TestRng {}


#[repr(align(8))]
pub struct AlignedBytes<const BYTE_LEN: usize>(pub(crate) [u8; BYTE_LEN]);


fn keygen_and_sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_INNER: usize = 5;
    const ITERATIONS_OUTER: usize = 2_000_000;

    let message = AlignedBytes::<8>([0u8, 1, 2, 3, 4, 5, 6, 7]);
    let z_left = AlignedBytes::<32>([0xAAu8; 32]);
    let z_right = AlignedBytes::<32>([0x55u8; 32]);


    let mut classes = vec![Class::Right; ITERATIONS_OUTER];
    let mut z_refs = vec![&z_right.0; ITERATIONS_OUTER];

    // Interleave left and right
    for i in (0..ITERATIONS_OUTER).step_by(2) {
        classes[i] = Class::Left;
        z_refs[i] = &z_left.0;
    }

    for (class, z) in classes.into_iter().zip(z_refs.into_iter()) {
        runner.run_one(class, || {
            let mut rng = TestRng(*z); // regurgitates z as rng
            for _ in 0..ITERATIONS_INNER {
                let _ = ml_dsa_44::dudect_keygen_sign_with_rng(&mut rng, &message.0);
            }
        })
    }
}

ctbench_main!(keygen_and_sign);

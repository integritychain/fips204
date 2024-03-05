use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use fips204::ml_dsa_44::PrivateKey;
use fips204::traits::Signer;

fn sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 1_000;
    const ITERATIONS_INNER: usize = 10;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (_pk1, sk1) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys
    let (_pk2, sk2) = ml_dsa_44::try_keygen_vt().unwrap();  // Generate both public and secret keys

    let mut inputs: Vec<PrivateKey> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk1.clone());
        classes.push(Class::Left);
    }

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk2.clone());
        classes.push(Class::Right);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let _ = input.try_sign_ct(&message);
            }
        })
    }
}

ctbench_main!(sign);

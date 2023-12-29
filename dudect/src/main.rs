use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87.
use fips204::ml_dsa_44::PrivateKey;
use fips204::traits::Signer;

fn sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 100;
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

/*
See https://docs.rs/dudect-bencher/latest/dudect_bencher/

$ cargo run --release -- --continuous sign
    Finished release [optimized] target(s) in 0.01s
     Running `target/release/fips204-dudect --continuous sign`
running 1 benchmark continuously
bench sign seeded with 0xffe537456435ccfe
bench sign ... : n == +0.000M, max t = -2.11233, max tau = -0.20421, (5/tau)^2 = 599
bench sign ... : n == +0.000M, max t = -2.28490, max tau = -0.15998, (5/tau)^2 = 976
bench sign ... : n == +0.000M, max t = -2.68228, max tau = -0.14256, (5/tau)^2 = 1230
bench sign ... : n == +0.000M, max t = -2.18286, max tau = -0.10090, (5/tau)^2 = 2455
bench sign ... : n == +0.000M, max t = -1.29318, max tau = -0.07162, (5/tau)^2 = 4873
bench sign ... : n == +0.001M, max t = +1.20683, max tau = +0.03631, (5/tau)^2 = 18967
bench sign ... : n == +0.001M, max t = +1.64937, max tau = +0.04528, (5/tau)^2 = 12194
bench sign ... : n == +0.001M, max t = -1.84583, max tau = -0.05927, (5/tau)^2 = 7117
bench sign ... : n == +0.001M, max t = -1.66518, max tau = -0.05034, (5/tau)^2 = 9863
bench sign ... : n == +0.001M, max t = -1.79038, max tau = -0.05136, (5/tau)^2 = 9476
bench sign ... : n == +0.002M, max t = +1.90319, max tau = +0.04058, (5/tau)^2 = 15184
bench sign ... : n == +0.002M, max t = +1.98307, max tau = +0.04048, (5/tau)^2 = 15257
bench sign ... : n == +0.002M, max t = -1.62882, max tau = -0.04046, (5/tau)^2 = 15274

*/
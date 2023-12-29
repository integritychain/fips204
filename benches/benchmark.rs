use criterion::{criterion_group, criterion_main, Criterion};
use fips204::traits::{PreGen, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};


pub fn criterion_benchmark(c: &mut Criterion) {
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (pk44, sk44) = ml_dsa_44::try_keygen_vt().unwrap();
    let precom44 = sk44.gen_precompute();
    let sig44 = sk44.try_sign_ct(&message).unwrap();

    let (pk65, sk65) = ml_dsa_65::try_keygen_vt().unwrap();
    let precom65 = sk65.gen_precompute();
    let sig65 = sk65.try_sign_ct(&message).unwrap();

    let (pk87, sk87) = ml_dsa_87::try_keygen_vt().unwrap();
    let precom87 = sk87.gen_precompute();
    let sig87 = sk87.try_sign_ct(&message).unwrap();


    c.bench_function("ml_dsa_44 keygen", |b| b.iter(|| ml_dsa_44::try_keygen_vt()));
    c.bench_function("ml_dsa_44 sign", |b| b.iter(|| sk44.try_sign_ct(&message)));
    c.bench_function("ml_dsa_44 precom sign", |b| b.iter(|| precom44.try_sign_ct(&message)));
    c.bench_function("ml_dsa 44 verify", |b| b.iter(|| pk44.try_verify_vt(&message, &sig44)));

    c.bench_function("ml_dsa_65 keygen", |b| b.iter(|| ml_dsa_65::try_keygen_vt()));
    c.bench_function("ml_dsa_65 sign", |b| b.iter(|| sk65.try_sign_ct(&message)));
    c.bench_function("ml_dsa_65 precom sign", |b| b.iter(|| precom65.try_sign_ct(&message)));
    c.bench_function("ml_dsa 65 verify", |b| b.iter(|| pk65.try_verify_vt(&message, &sig65)));

    c.bench_function("ml_dsa_87 keygen", |b| b.iter(|| ml_dsa_87::try_keygen_vt()));
    c.bench_function("ml_dsa_87 sign", |b| b.iter(|| sk87.try_sign_ct(&message)));
    c.bench_function("ml_dsa_87 precom sign", |b| b.iter(|| precom87.try_sign_ct(&message)));
    c.bench_function("ml_dsa 87 verify", |b| b.iter(|| pk87.try_verify_vt(&message, &sig87)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// cargo bench
// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Prior to any optimization
//    ml_dsa_44 keygen        time:   [158.58 µs 158.62 µs 158.66 µs]
//    ml_dsa_65 keygen        time:   [270.23 µs 270.49 µs 270.97 µs]
//    ml_dsa_87 keygen        time:   [388.72 µs 388.85 µs 389.02 µs]
//
//    ml_dsa_44 sign          time:   [1.0791 ms 1.1022 ms 1.1259 ms]
//    ml_dsa_65 sign          time:   [1.7349 ms 1.7702 ms 1.8063 ms]
//    ml_dsa_87 sign          time:   [1.9371 ms 1.9865 ms 2.0369 ms]
//
//    ml_dsa 44 verify        time:   [259.54 µs 260.31 µs 261.33 µs]
//    ml_dsa 65 verify        time:   [436.95 µs 437.18 µs 437.46 µs]
//    ml_dsa 87 verify        time:   [695.26 µs 697.27 µs 701.48 µs]

// As of 12-29-23
//    ml_dsa_44 keygen        time:   [110.83 µs 110.94 µs 111.07 µs]
//    ml_dsa_65 keygen        time:   [200.49 µs 200.51 µs 200.53 µs]
//    ml_dsa_87 keygen        time:   [296.69 µs 296.80 µs 296.95 µs]
//
//    ml_dsa_44 sign          time:   [469.57 µs 475.28 µs 480.97 µs]
//    ml_dsa_65 sign          time:   [759.66 µs 772.35 µs 784.82 µs]
//    ml_dsa_87 sign          time:   [910.47 µs 919.20 µs 928.21 µs]
//
//    ml_dsa 44 verify        time:   [151.33 µs 151.48 µs 151.68 µs]
//    ml_dsa 65 verify        time:   [266.43 µs 266.63 µs 266.87 µs]
//    ml_dsa 87 verify        time:   [436.12 µs 436.36 µs 436.69 µs]

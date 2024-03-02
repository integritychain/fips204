use criterion::{criterion_group, criterion_main, Criterion};
use fips204::traits::{Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};


#[allow(clippy::redundant_closure)]
pub fn criterion_benchmark(c: &mut Criterion) {
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (pk44, sk44) = ml_dsa_44::try_keygen_vt().unwrap();
    let sig44 = sk44.try_sign_ct(&message).unwrap();

    let (pk65, sk65) = ml_dsa_65::try_keygen_vt().unwrap();
    let sig65 = sk65.try_sign_ct(&message).unwrap();

    let (pk87, sk87) = ml_dsa_87::try_keygen_vt().unwrap();
    let sig87 = sk87.try_sign_ct(&message).unwrap();

    c.bench_function("ml_dsa_44 keygen", |b| b.iter(|| ml_dsa_44::try_keygen_vt()));
    c.bench_function("ml_dsa_65 keygen", |b| b.iter(|| ml_dsa_65::try_keygen_vt()));
    c.bench_function("ml_dsa_87 keygen", |b| b.iter(|| ml_dsa_87::try_keygen_vt()));

    c.bench_function("ml_dsa_44 sign", |b| b.iter(|| sk44.try_sign_ct(&message)));
    c.bench_function("ml_dsa_65 sign", |b| b.iter(|| sk65.try_sign_ct(&message)));
    c.bench_function("ml_dsa_87 sign", |b| b.iter(|| sk87.try_sign_ct(&message)));

    c.bench_function("ml_dsa 44 verify", |b| b.iter(|| pk44.try_verify_vt(&message, &sig44)));
    c.bench_function("ml_dsa 65 verify", |b| b.iter(|| pk65.try_verify_vt(&message, &sig65)));
    c.bench_function("ml_dsa 87 verify", |b| b.iter(|| pk87.try_verify_vt(&message, &sig87)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion};
use fips204::traits::{KeyGen, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};


#[allow(clippy::redundant_closure)]
pub fn criterion_benchmark(c: &mut Criterion) {
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (pk44, sk44) = ml_dsa_44::try_keygen_vt().unwrap();
    let esk44 = ml_dsa_44::KG::gen_expanded_private_vt(&sk44).unwrap();
    let epk44 = ml_dsa_44::KG::gen_expanded_public_vt(&pk44).unwrap();
    let sig44 = sk44.try_sign_ct(&message).unwrap();

    let (pk65, sk65) = ml_dsa_65::try_keygen_vt().unwrap();
    let esk65 = ml_dsa_65::KG::gen_expanded_private_vt(&sk65).unwrap();
    let epk65 = ml_dsa_65::KG::gen_expanded_public_vt(&pk65).unwrap();
    let sig65 = sk65.try_sign_ct(&message).unwrap();

    let (pk87, sk87) = ml_dsa_87::try_keygen_vt().unwrap();
    let esk87 = ml_dsa_87::KG::gen_expanded_private_vt(&sk87).unwrap();
    let epk87 = ml_dsa_87::KG::gen_expanded_public_vt(&pk87).unwrap();
    let sig87 = sk87.try_sign_ct(&message).unwrap();

    c.bench_function("ml_dsa_44 keygen", |b| b.iter(|| ml_dsa_44::try_keygen_vt()));
    c.bench_function("ml_dsa_65 keygen", |b| b.iter(|| ml_dsa_65::try_keygen_vt()));
    c.bench_function("ml_dsa_87 keygen", |b| b.iter(|| ml_dsa_87::try_keygen_vt()));

    c.bench_function("ml_dsa_44 sk sign", |b| b.iter(|| sk44.try_sign_ct(&message)));
    c.bench_function("ml_dsa_65 sk sign", |b| b.iter(|| sk65.try_sign_ct(&message)));
    c.bench_function("ml_dsa_87 sk sign", |b| b.iter(|| sk87.try_sign_ct(&message)));

    c.bench_function("ml_dsa_44 esk sign", |b| b.iter(|| esk44.try_sign_ct(&message)));
    c.bench_function("ml_dsa_65 esk sign", |b| b.iter(|| esk65.try_sign_ct(&message)));
    c.bench_function("ml_dsa_87 esk sign", |b| b.iter(|| esk87.try_sign_ct(&message)));

    c.bench_function("ml_dsa 44 pk verify", |b| b.iter(|| pk44.try_verify_vt(&message, &sig44)));
    c.bench_function("ml_dsa 65 pk verify", |b| b.iter(|| pk65.try_verify_vt(&message, &sig65)));
    c.bench_function("ml_dsa 87 pk verify", |b| b.iter(|| pk87.try_verify_vt(&message, &sig87)));

    c.bench_function("ml_dsa 44 epk verify", |b| b.iter(|| epk44.try_verify_vt(&message, &sig44)));
    c.bench_function("ml_dsa 65 epk verify", |b| b.iter(|| epk65.try_verify_vt(&message, &sig65)));
    c.bench_function("ml_dsa 87 epk verify", |b| b.iter(|| epk87.try_verify_vt(&message, &sig87)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

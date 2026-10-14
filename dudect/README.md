Constant-time measurement of `fips204` key generation and signing with
[dudect-bencher](https://docs.rs/dudect-bencher/0.6.0/dudect_bencher/). Each sample generates an
ML-DSA-44 key pair and signs a fixed message with it, five times. The `dudect` feature's
`dudect_keygen_sign_with_rng` makes each signature a single attempt and removes timing variation
that comes only from non-secret data, such as rejection sampling of values derived from rho. The two
classes use different fixed seeds and signing randomness (every byte 0xAA, or every byte 0x55) and
alternate sample by sample, so a timing difference between two keys shows up as a large t-value.
Results depend on the machine and configuration; they are evidence, not proof.

Depends on crates.io `dudect-bencher` 0.6 and `rand_core` 0.6.4, the same RNG
line as `fips204`.

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 14, 2026
13th Gen Intel® Core™ i7-13700K × 24  Circa 2022  Rust 1.98.1  fips204 v0.5.0

$ cd dudect  # this directory
$ cargo +stable clean
     Removed 0 files
$ time RUSTFLAGS="-C target-cpu=native" taskset -c 12 cargo +stable run --release  # A ~8 minute run on one P-core

...
    Finished `release` profile [optimized + debuginfo] target(s) in 19.12s
     Running `target/release/fips204-dudect`

running 1 bench
bench keygen_and_sign seeded with 0x5eeb98ba6db29056
bench keygen_and_sign ... : n == +1.044M, max t = +1.58916, max tau = +0.00156, (5/tau)^2 = 10336778

dudect benches complete


real	8m22.583s
user	8m21.036s
sys	0m1.416s
~~~

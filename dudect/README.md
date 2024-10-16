An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 16, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.81

$ cd dudect  # this directory
$ cargo clean
$ time RUSTFLAGS="-C target-cpu=native" cargo run --release

...
   Compiling fips204 v0.4.3 (/home/eric/work/fips204)
   Compiling fips204-dudect v0.4.3 (/home/eric/work/fips204/dudect)
    Finished `release` profile [optimized + debuginfo] target(s) in 20.92s
     Running `target/release/fips204-dudect`

running 1 bench
bench keygen_and_sign seeded with 0xef78035f1caaa970
bench keygen_and_sign ... : n == +1.049M, max t = +0.89328, max tau = +0.00087, (5/tau)^2 = 32852562

dudect benches complete


real	14m5.190s
user	14m20.882s
~~~
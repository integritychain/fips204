An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
September 29, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.81

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release

...
   Compiling fips204-dudect v0.4.0 (/home/eric/work/fips204/dudect)
    Finished `release` profile [optimized + debuginfo] target(s) in 19.97s
     Running `target/release/fips204-dudect`

running 1 bench
bench keygen_and_sign seeded with 0x5a426c75ebe1613a
bench keygen_and_sign ... : n == +1.188M, max t = +3.14225, max tau = +0.00288, (5/tau)^2 = 3007343

dudect benches complete
~~~
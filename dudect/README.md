An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
May 22, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.70

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous keygen_and_sign

bench keygen_and_sign seeded with 0x826d7088eeda2cad
bench keygen_and_sign ... : n == +0.102M, max t = -1.97046, max tau = -0.00616, (5/tau)^2 = 659312
bench keygen_and_sign ... : n == +0.260M, max t = -2.25947, max tau = -0.00443, (5/tau)^2 = 1271689
bench keygen_and_sign ... : n == +0.388M, max t = -2.81974, max tau = -0.00453, (5/tau)^2 = 1220064
bench keygen_and_sign ... : n == +0.519M, max t = -2.66709, max tau = -0.00370, (5/tau)^2 = 1823937
bench keygen_and_sign ... : n == +0.657M, max t = -2.92324, max tau = -0.00361, (5/tau)^2 = 1920968
bench keygen_and_sign ... : n == +0.779M, max t = -3.22059, max tau = -0.00365, (5/tau)^2 = 1878485
bench keygen_and_sign ... : n == +0.923M, max t = -3.54252, max tau = -0.00369, (5/tau)^2 = 1839152
bench keygen_and_sign ... : n == +1.065M, max t = -4.01591, max tau = -0.00389, (5/tau)^2 = 1651285
...
~~~
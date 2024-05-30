An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
May 30, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.70

$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous keygen_and_sign

bench keygen_and_sign seeded with 0x487b8e4779e6365c
bench keygen_and_sign ... : n == +0.013M, max t = -1.88608, max tau = -0.01630, (5/tau)^2 = 94059
bench keygen_and_sign ... : n == +0.226M, max t = -1.97079, max tau = -0.00414, (5/tau)^2 = 1456142
bench keygen_and_sign ... : n == +0.332M, max t = -2.46353, max tau = -0.00428, (5/tau)^2 = 1367236
bench keygen_and_sign ... : n == +0.437M, max t = -3.09049, max tau = -0.00467, (5/tau)^2 = 1144967
bench keygen_and_sign ... : n == +0.546M, max t = -3.36390, max tau = -0.00455, (5/tau)^2 = 1205380
bench keygen_and_sign ... : n == +0.653M, max t = -3.20033, max tau = -0.00396, (5/tau)^2 = 1594027
bench keygen_and_sign ... : n == +0.763M, max t = -2.93715, max tau = -0.00336, (5/tau)^2 = 2212470
bench keygen_and_sign ... : n == +1.535M, max t = -2.52898, max tau = -0.00204, (5/tau)^2 = 6001424
bench keygen_and_sign ... : n == +1.728M, max t = -3.02826, max tau = -0.00230, (5/tau)^2 = 4710906
bench keygen_and_sign ... : n == +1.921M, max t = -2.54927, max tau = -0.00184, (5/tau)^2 = 7389844
bench keygen_and_sign ... : n == +2.113M, max t = -2.69149, max tau = -0.00185, (5/tau)^2 = 7293214
...
~~~
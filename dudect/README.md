
Need to rework the rng (to return hardcoded values)

~~~
See https://docs.rs/dudect-bencher/latest/dudect_bencher/

$ RUSTFLAGS="-C target-cpu=native" cargo run --release
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous sign
running 1 benchmark continuously
bench sign seeded with 0x9eddf0cb1f0a9394
bench sign ... : n == +0.001M, max t = -1.74343, max tau = -0.05337, (5/tau)^2 = 8776
bench sign ... : n == +0.004M, max t = +1.30450, max tau = +0.02111, (5/tau)^2 = 56105
bench sign ... : n == +0.006M, max t = +2.70976, max tau = +0.03579, (5/tau)^2 = 19519
bench sign ... : n == +0.008M, max t = +1.72776, max tau = +0.01975, (5/tau)^2 = 64091
bench sign ... : n == +0.010M, max t = +2.67128, max tau = +0.02695, (5/tau)^2 = 34428
bench sign ... : n == +0.012M, max t = +2.25015, max tau = +0.02098, (5/tau)^2 = 56802
bench sign ... : n == +0.014M, max t = +2.15358, max tau = +0.01844, (5/tau)^2 = 73502
bench sign ... : n == +0.015M, max t = +2.17601, max tau = +0.01778, (5/tau)^2 = 79081
bench sign ... : n == +0.017M, max t = +1.73582, max tau = +0.01338, (5/tau)^2 = 139641
bench sign ... : n == +0.019M, max t = +1.42413, max tau = +0.01041, (5/tau)^2 = 230567
~~~
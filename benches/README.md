Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
April 27, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [94.188 µs 94.246 µs 94.316 µs]
ml_dsa_65 keygen        time:   [176.93 µs 177.11 µs 177.24 µs]
ml_dsa_87 keygen        time:   [254.57 µs 254.61 µs 254.65 µs]

ml_dsa_44 sk sign       time:   [392.25 µs 395.71 µs 399.07 µs]
ml_dsa_65 sk sign       time:   [622.84 µs 630.79 µs 638.92 µs]
ml_dsa_87 sk sign       time:   [760.41 µs 771.05 µs 781.59 µs]

ml_dsa_44 esk sign      time:   [330.93 µs 335.40 µs 339.92 µs]  // Fast sign, 15% improvement
ml_dsa_65 esk sign      time:   [499.83 µs 507.04 µs 514.29 µs]
ml_dsa_87 esk sign      time:   [548.43 µs 556.40 µs 564.54 µs]

ml_dsa 44 pk verify     time:   [128.95 µs 129.21 µs 129.55 µs]
ml_dsa 65 pk verify     time:   [228.24 µs 228.27 µs 228.32 µs]
ml_dsa 87 pk verify     time:   [390.17 µs 390.25 µs 390.33 µs]

ml_dsa 44 epk verify    time:   [70.176 µs 70.263 µs 70.385 µs]  // Fast verify, 46% improvement
ml_dsa 65 epk verify    time:   [124.36 µs 124.40 µs 124.44 µs]
ml_dsa 87 epk verify    time:   [208.15 µs 208.22 µs 208.31 µs]
~~~
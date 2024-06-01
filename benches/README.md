Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 31, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.78.0

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [79.674 µs 79.754 µs 79.877 µs]
ml_dsa_65 keygen        time:   [149.41 µs 149.44 µs 149.47 µs]
ml_dsa_87 keygen        time:   [216.21 µs 217.08 µs 218.12 µs]

ml_dsa_44 sk sign       time:   [290.51 µs 293.15 µs 295.84 µs]
ml_dsa_65 sk sign       time:   [443.48 µs 448.59 µs 454.09 µs]
ml_dsa_87 sk sign       time:   [558.96 µs 566.32 µs 573.92 µs]

ml_dsa_44 esk sign      time:   [231.09 µs 233.74 µs 236.46 µs]
ml_dsa_65 esk sign      time:   [337.80 µs 341.81 µs 345.84 µs]
ml_dsa_87 esk sign      time:   [376.49 µs 382.48 µs 388.55 µs]

ml_dsa_44 pk verify     time:   [74.478 µs 74.909 µs 75.334 µs]
ml_dsa_65 pk verify     time:   [120.80 µs 121.28 µs 121.79 µs]
ml_dsa_87 pk verify     time:   [202.96 µs 203.28 µs 203.68 µs]

ml_dsa_44 epk verify    time:   [20.728 µs 20.743 µs 20.758 µs]
ml_dsa_65 epk verify    time:   [26.153 µs 26.159 µs 26.166 µs]
ml_dsa_87 epk verify    time:   [35.696 µs 35.715 µs 35.729 µs]
~~~
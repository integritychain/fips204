Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 10, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [85.502 µs 85.521 µs 85.543 µs]
ml_dsa_65 keygen        time:   [162.17 µs 162.23 µs 162.34 µs]
ml_dsa_87 keygen        time:   [232.24 µs 232.26 µs 232.28 µs]

ml_dsa_44 sk sign       time:   [301.10 µs 303.62 µs 306.12 µs]
ml_dsa_65 sk sign       time:   [486.54 µs 491.62 µs 496.69 µs]
ml_dsa_87 sk sign       time:   [593.29 µs 599.69 µs 606.20 µs]

ml_dsa_44 esk sign      time:   [233.84 µs 236.39 µs 239.00 µs]
ml_dsa_65 esk sign      time:   [375.86 µs 380.61 µs 385.48 µs]
ml_dsa_87 esk sign      time:   [401.26 µs 406.48 µs 411.66 µs]

ml_dsa 44 pk verify     time:   [78.619 µs 78.630 µs 78.640 µs]
ml_dsa 65 pk verify     time:   [130.59 µs 130.64 µs 130.69 µs]
ml_dsa 87 pk verify     time:   [219.01 µs 219.06 µs 219.12 µs]

ml_dsa 44 epk verify    time:   [20.677 µs 20.694 µs 20.712 µs]
ml_dsa 65 epk verify    time:   [26.972 µs 26.980 µs 26.987 µs]
ml_dsa 87 epk verify    time:   [36.188 µs 36.203 µs 36.218 µs]
~~~
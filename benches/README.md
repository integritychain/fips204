Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
September 27, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.81.0

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [79.427 µs 79.563 µs 79.743 µs]
ml_dsa_65 keygen        time:   [149.51 µs 149.54 µs 149.59 µs]
ml_dsa_87 keygen        time:   [214.53 µs 214.62 µs 214.77 µs]

ml_dsa_44 sk sign       time:   [285.42 µs 288.21 µs 291.02 µs]
ml_dsa_65 sk sign       time:   [442.89 µs 447.03 µs 451.31 µs]
ml_dsa_87 sk sign       time:   [567.67 µs 574.08 µs 580.57 µs]

ml_dsa_44 esk sign      time:   [224.79 µs 227.11 µs 229.49 µs]
ml_dsa_65 esk sign      time:   [338.46 µs 343.11 µs 347.75 µs]
ml_dsa_87 esk sign      time:   [384.39 µs 388.84 µs 393.61 µs]

ml_dsa_44 pk verify     time:   [72.814 µs 72.833 µs 72.854 µs]
ml_dsa_65 pk verify     time:   [121.24 µs 121.29 µs 121.35 µs]
ml_dsa_87 pk verify     time:   [200.09 µs 200.23 µs 200.41 µs]

ml_dsa_44 epk verify    time:   [20.932 µs 20.966 µs 21.009 µs]
ml_dsa_65 epk verify    time:   [26.543 µs 26.548 µs 26.554 µs]
ml_dsa_87 epk verify    time:   [35.872 µs 35.886 µs 35.900 µs]
~~~
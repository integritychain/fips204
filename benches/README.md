Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 2, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [96.321 µs 96.430 µs 96.588 µs]
ml_dsa_65 keygen        time:   [178.26 µs 180.06 µs 182.69 µs]
ml_dsa_87 keygen        time:   [260.61 µs 261.11 µs 262.06 µs]

ml_dsa_44 sk sign       time:   [373.45 µs 376.67 µs 379.81 µs]
ml_dsa_65 sk sign       time:   [644.92 µs 653.32 µs 662.09 µs]
ml_dsa_87 sk sign       time:   [777.73 µs 788.49 µs 799.28 µs]

ml_dsa_44 esk sign      time:   [307.48 µs 311.03 µs 314.53 µs]
ml_dsa_65 esk sign      time:   [525.53 µs 533.96 µs 541.88 µs]
ml_dsa_87 esk sign      time:   [552.76 µs 562.43 µs 572.18 µs]

ml_dsa 44 pk verify     time:   [135.45 µs 135.48 µs 135.53 µs]
ml_dsa 65 pk verify     time:   [231.73 µs 231.76 µs 231.81 µs]
ml_dsa 87 pk verify     time:   [424.19 µs 424.34 µs 424.55 µs]

ml_dsa 44 epk verify    time:   [75.541 µs 75.563 µs 75.585 µs]
ml_dsa 65 epk verify    time:   [124.11 µs 124.25 µs 124.41 µs]
ml_dsa 87 epk verify    time:   [236.60 µs 236.74 µs 236.91 µs]
~~~
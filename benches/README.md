Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 1, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [91.264 µs 91.402 µs 91.555 µs]
ml_dsa_65 keygen        time:   [169.11 µs 169.23 µs 169.39 µs]
ml_dsa_87 keygen        time:   [247.51 µs 247.91 µs 248.34 µs]

ml_dsa_44 sk sign       time:   [369.67 µs 373.75 µs 378.01 µs]
ml_dsa_65 sk sign       time:   [597.12 µs 606.37 µs 615.55 µs]
ml_dsa_87 sk sign       time:   [734.89 µs 742.40 µs 750.00 µs]

ml_dsa_44 esk sign      time:   [313.36 µs 317.30 µs 321.32 µs] // Fast sign, 15% improvement
ml_dsa_65 esk sign      time:   [495.20 µs 505.25 µs 515.57 µs]
ml_dsa_87 esk sign      time:   [532.84 µs 541.26 µs 550.20 µs]

ml_dsa 44 pk verify     time:   [129.28 µs 129.40 µs 129.55 µs]
ml_dsa 65 pk verify     time:   [223.02 µs 223.11 µs 223.23 µs]
ml_dsa 87 pk verify     time:   [381.66 µs 382.84 µs 384.46 µs]

ml_dsa 44 epk verify    time:   [71.255 µs 71.320 µs 71.414 µs] // Fast verif, 45% improvement
ml_dsa 65 epk verify    time:   [123.49 µs 123.57 µs 123.67 µs]
ml_dsa 87 epk verify    time:   [205.28 µs 205.45 µs 205.65 µs]
~~~
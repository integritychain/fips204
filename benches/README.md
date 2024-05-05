Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 5, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [85.256 µs 85.275 µs 85.299 µs]
ml_dsa_65 keygen        time:   [160.99 µs 161.04 µs 161.10 µs]
ml_dsa_87 keygen        time:   [233.85 µs 233.92 µs 233.99 µs]

ml_dsa_44 sk sign       time:   [306.79 µs 309.50 µs 312.14 µs]
ml_dsa_65 sk sign       time:   [519.89 µs 525.77 µs 531.68 µs]
ml_dsa_87 sk sign       time:   [638.39 µs 645.71 µs 653.05 µs]

ml_dsa_44 esk sign      time:   [247.20 µs 250.01 µs 252.94 µs]
ml_dsa_65 esk sign      time:   [423.54 µs 429.68 µs 435.97 µs]
ml_dsa_87 esk sign      time:   [453.37 µs 458.29 µs 463.27 µs]

ml_dsa 44 pk verify     time:   [75.202 µs 75.216 µs 75.231 µs]
ml_dsa 65 pk verify     time:   [135.17 µs 135.19 µs 135.22 µs]
ml_dsa 87 pk verify     time:   [224.04 µs 224.18 µs 224.35 µs]

ml_dsa 44 epk verify    time:   [22.837 µs 22.847 µs 22.856 µs]
ml_dsa 65 epk verify    time:   [38.911 µs 38.923 µs 38.934 µs]
ml_dsa 87 epk verify    time:   [56.317 µs 56.346 µs 56.374 µs]
~~~
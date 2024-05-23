Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

Additional performance optimizations will follow the next update to FIPS 204.
Near-obvious uplift can be had with more careful modular multiplication & addition
using fewer reductions. Also, 'u16' arithmetic has a performance penalty.

~~~
May 23, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.77.2

$ RUSTFLAGS="-C target-cpu=native" cargo bench

ml_dsa_44 keygen        time:   [81.914 µs 82.700 µs 83.926 µs]
ml_dsa_65 keygen        time:   [156.96 µs 157.10 µs 157.27 µs]
ml_dsa_87 keygen        time:   [218.36 µs 218.39 µs 218.43 µs]

ml_dsa_44 sk sign       time:   [294.03 µs 296.72 µs 299.43 µs]
ml_dsa_65 sk sign       time:   [467.49 µs 471.89 µs 476.52 µs]
ml_dsa_87 sk sign       time:   [563.69 µs 571.15 µs 578.91 µs]

ml_dsa_44 esk sign      time:   [234.98 µs 237.67 µs 240.41 µs]
ml_dsa_65 esk sign      time:   [369.19 µs 373.82 µs 378.42 µs]
ml_dsa_87 esk sign      time:   [377.20 µs 383.07 µs 388.71 µs]

ml_dsa_44 pk verify     time:   [74.240 µs 74.313 µs 74.391 µs]
ml_dsa_65 pk verify     time:   [123.13 µs 123.21 µs 123.31 µs]
ml_dsa_87 pk verify     time:   [204.39 µs 204.70 µs 205.27 µs]

ml_dsa_44 epk verify    time:   [21.200 µs 21.232 µs 21.264 µs]
ml_dsa_65 epk verify    time:   [26.797 µs 26.815 µs 26.830 µs]
ml_dsa_87 epk verify    time:   [36.227 µs 36.249 µs 36.265 µs]
~~~
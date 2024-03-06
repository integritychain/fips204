
Figure-of-merit ... no particular care taken to disable turbo boost etc

~~~
// $ RUSTFLAGS="-C target-cpu=native" cargo bench
// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Mar 6 2024

ml_dsa_44 keygen        time:   [97.518 µs 97.535 µs 97.552 µs]
ml_dsa_65 keygen        time:   [179.85 µs 180.16 µs 180.75 µs]
ml_dsa_87 keygen        time:   [263.45 µs 263.65 µs 263.91 µs]

ml_dsa_44 sk sign       time:   [364.11 µs 367.89 µs 371.69 µs]
ml_dsa_65 sk sign       time:   [591.80 µs 600.07 µs 608.24 µs]
ml_dsa_87 sk sign       time:   [724.66 µs 733.22 µs 741.71 µs]

ml_dsa_44 esk sign      time:   [297.77 µs 301.36 µs 305.08 µs]  // 18% improvement
ml_dsa_65 esk sign      time:   [474.79 µs 481.79 µs 489.26 µs]
ml_dsa_87 esk sign      time:   [513.10 µs 520.88 µs 528.78 µs]

ml_dsa 44 pk verify     time:   [138.94 µs 139.08 µs 139.25 µs]
ml_dsa 65 pk verify     time:   [225.74 µs 225.77 µs 225.79 µs]
ml_dsa 87 pk verify     time:   [400.09 µs 400.20 µs 400.32 µs]

ml_dsa 44 epk verify    time:   [78.406 µs 78.477 µs 78.551 µs]  // 43% improvement
ml_dsa 65 epk verify    time:   [117.81 µs 117.86 µs 117.90 µs]
ml_dsa 87 epk verify    time:   [219.52 µs 219.68 µs 219.84 µs]
~~~
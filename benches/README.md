
Figure-of-merit ... no particular care taken to disable turbo boost etc

~~~
// $ RUSTFLAGS="-C target-cpu=native" cargo bench
// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Mar 2 2024

ml_dsa_44 keygen        time:   [100.58 µs 100.59 µs 100.60 µs]
ml_dsa_65 keygen        time:   [182.64 µs 182.66 µs 182.70 µs]
ml_dsa_87 keygen        time:   [274.29 µs 274.32 µs 274.34 µs]

ml_dsa_44 sign          time:   [375.30 µs 379.30 µs 383.24 µs]
ml_dsa_65 sign          time:   [607.69 µs 615.36 µs 622.80 µs]
ml_dsa_87 sign          time:   [718.89 µs 725.54 µs 732.38 µs]

ml_dsa 44 verify        time:   [132.27 µs 132.31 µs 132.36 µs]
ml_dsa 65 verify        time:   [235.82 µs 236.06 µs 236.29 µs]
ml_dsa 87 verify        time:   [390.08 µs 391.85 µs 394.34 µs]
~~~
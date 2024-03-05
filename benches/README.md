
Figure-of-merit ... no particular care taken to disable turbo boost etc

~~~
// $ RUSTFLAGS="-C target-cpu=native" cargo bench
// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Mar 5 2024

ml_dsa_44 keygen        time:   [92.030 µs 92.113 µs 92.266 µs]
ml_dsa_65 keygen        time:   [168.05 µs 168.07 µs 168.09 µs]
ml_dsa_87 keygen        time:   [244.87 µs 244.96 µs 245.05 µs]

ml_dsa_44 sign          time:   [361.25 µs 365.44 µs 369.65 µs]
ml_dsa_65 sign          time:   [589.35 µs 598.81 µs 608.16 µs]
ml_dsa_87 sign          time:   [718.22 µs 726.95 µs 735.49 µs]

ml_dsa 44 verify        time:   [118.81 µs 118.86 µs 118.95 µs]
ml_dsa 65 verify        time:   [216.02 µs 216.04 µs 216.07 µs]
ml_dsa 87 verify        time:   [351.97 µs 351.99 µs 352.01 µs]
~~~
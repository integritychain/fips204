Figure-of-merit only; no particular care has been taken to disable turbo-boost etc. Note that constant-time restrictions
on the implementation do impact performance. Also, keys do not store the expanded matrix Â in order to keep memory down
and avoid the stack copies that can overflow in unoptimized dev builds. Verify is mostly that matrix rebuild, so it is
the slow part of the measurement. This may change in future with the expanded matrix Â stored on the key.

~~~
October 1, 2026
13th Gen Intel® Core™ i7-13700K, Rust 1.85.1
Bench profile: opt-level 3, LTO, codegen-units 1, overflow checks off.
Turbo Boost was left enabled.

$ RUSTFLAGS="-C target-cpu=native" cargo bench --bench benchmark

ml_dsa_44 keygen        time:   [58.932 µs 59.042 µs 59.203 µs]
ml_dsa_65 keygen        time:   [104.46 µs 104.53 µs 104.60 µs]
ml_dsa_87 keygen        time:   [148.55 µs 148.60 µs 148.65 µs]

ml_dsa_44 sk sign       time:   [171.52 µs 172.75 µs 174.01 µs]
ml_dsa_65 sk sign       time:   [254.79 µs 257.61 µs 260.38 µs]
ml_dsa_87 sk sign       time:   [299.80 µs 302.34 µs 304.81 µs]

ml_dsa_44 pk verify     time:   [37.127 µs 37.139 µs 37.152 µs]
ml_dsa_65 pk verify     time:   [61.871 µs 61.904 µs 61.943 µs]
ml_dsa_87 pk verify     time:   [105.77 µs 105.85 µs 105.95 µs]
~~~

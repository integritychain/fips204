This is a work in progress, but good results currently.

Harness code is in fuzz/fuzz_targets/fuzz_all.rs. The Cargo.toml file specifies 
that overflow-checks and debug-assertions are enabled (so the fuzzer can find these panics).

See <https://rust-fuzz.github.io/book/introduction.html>

~~~
$ cd fuzz  # this directory; you may need to install cargo fuzz
$ rustup default nightly
$ mkdir -p corpus/fuzz_all
$ dd if=/dev/zero bs=1 count=6292 > corpus/fuzz_all/seed0
$ for i in $(seq 1 2); do head -c 6292 </dev/urandom > corpus/fuzz_all/seed$i; done
$ dd if=/dev/zero bs=1 count=6292 | tr '\0x00' '\377' > corpus/fuzz_all/seed3
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=1000  # run twice

#1054: cov: 13559 ft: 10028 corp: 102 exec/s 0 oom/timeout/crash: 0/0/0 time: 899s job: 60 dft_time: 0
#1084: cov: 13559 ft: 10028 corp: 102 exec/s 0 oom/timeout/crash: 0/0/0 time: 913s job: 61 dft_time: 0
#1124: cov: 13559 ft: 10028 corp: 102 exec/s 0 oom/timeout/crash: 0/0/0 time: 936s job: 62 dft_time: 0
#1170: cov: 13559 ft: 10134 corp: 104 exec/s 0 oom/timeout/crash: 0/0/0 time: 954s job: 63 dft_time: 0
#1207: cov: 13559 ft: 10135 corp: 105 exec/s 0 oom/timeout/crash: 0/0/0 time: 970s job: 64 dft_time: 0
#1240: cov: 13559 ft: 10135 corp: 105 exec/s 0 oom/timeout/crash: 0/0/0 time: 985s job: 65 dft_time: 0
INFO: fuzzed for 1001 seconds, wrapping up soon
INFO: exiting: 0 time: 1004s
~~~

Coverage status of ml_dsa_44 is robust, see:

~~~
$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~
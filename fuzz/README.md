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
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=1000  # run three times

#1020: cov: 13306 ft: 9885 corp: 153 exec/s 0 oom/timeout/crash: 0/0/0 time: 867s job: 50 dft_time: 0
#1046: cov: 13306 ft: 9910 corp: 155 exec/s 0 oom/timeout/crash: 0/0/0 time: 883s job: 51 dft_time: 0
#1096: cov: 13306 ft: 9912 corp: 156 exec/s 0 oom/timeout/crash: 0/0/0 time: 905s job: 52 dft_time: 0
#1132: cov: 13306 ft: 9912 corp: 156 exec/s 0 oom/timeout/crash: 0/0/0 time: 914s job: 53 dft_time: 0
#1184: cov: 13306 ft: 9913 corp: 157 exec/s 0 oom/timeout/crash: 0/0/0 time: 927s job: 54 dft_time: 0
#1245: cov: 13306 ft: 9985 corp: 160 exec/s 1 oom/timeout/crash: 0/0/0 time: 945s job: 55 dft_time: 0
#1270: cov: 13306 ft: 9985 corp: 160 exec/s 0 oom/timeout/crash: 0/0/0 time: 964s job: 56 dft_time: 0
#1297: cov: 13306 ft: 9990 corp: 162 exec/s 0 oom/timeout/crash: 0/0/0 time: 979s job: 57 dft_time: 0
#1331: cov: 13306 ft: 9997 corp: 164 exec/s 0 oom/timeout/crash: 0/0/0 time: 996s job: 58 dft_time: 0
INFO: fuzzed for 1005 seconds, wrapping up soon
INFO: exiting: 0 time: 1019s
~~~

Coverage status of ml_dsa_44 is robust, see:

~~~
$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~
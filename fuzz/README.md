This is a work in progress, but good results currently.

Harness code is in fuzz/fuzz_targets/*. The Cargo.toml file specifies that overflow-checks and 
debug-assertions are enabled (so the fuzzer can find these panics).

See <https://rust-fuzz.github.io/book/introduction.html>

~~~
$ cd fuzz  # this directory; you may need to install cargo fuzz
$ rustup default nightly
$ mkdir -p corpus/fuzz_all
$ dd if=/dev/zero bs=1 count=6292 > corpus/fuzz_all/seed0
$ for i in $(seq 1 2); do head -c 6292 </dev/urandom > corpus/fuzz_all/seed$i; done
$ dd if=/dev/zero bs=1 count=6292 | tr '\0x00' '\377' > corpus/fuzz_all/seed3
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=1000  # run three times

#1184: cov: 13306 ft: 9913 corp: 157 exec/s 0 oom/timeout/crash: 0/0/0 time: 927s job: 54 dft_time: 0
#1245: cov: 13306 ft: 9985 corp: 160 exec/s 1 oom/timeout/crash: 0/0/0 time: 945s job: 55 dft_time: 0
#1270: cov: 13306 ft: 9985 corp: 160 exec/s 0 oom/timeout/crash: 0/0/0 time: 964s job: 56 dft_time: 0
#1297: cov: 13306 ft: 9990 corp: 162 exec/s 0 oom/timeout/crash: 0/0/0 time: 979s job: 57 dft_time: 0
#1331: cov: 13306 ft: 9997 corp: 164 exec/s 0 oom/timeout/crash: 0/0/0 time: 996s job: 58 dft_time: 0
INFO: fuzzed for 1005 seconds, wrapping up soon
INFO: exiting: 0 time: 1019s


$ cargo fuzz run fuzz_sign -j 4 -- -max_total_time=1000

#241: cov: 18829 ft: 12381 corp: 18 exec/s 0 oom/timeout/crash: 0/0/0 time: 890s job: 63 dft_time: 0
#247: cov: 18829 ft: 12474 corp: 19 exec/s 0 oom/timeout/crash: 0/0/0 time: 905s job: 64 dft_time: 0
#253: cov: 18829 ft: 12575 corp: 20 exec/s 0 oom/timeout/crash: 0/0/0 time: 952s job: 65 dft_time: 0
#259: cov: 18829 ft: 12588 corp: 21 exec/s 0 oom/timeout/crash: 0/0/0 time: 968s job: 66 dft_time: 0
#266: cov: 18829 ft: 12702 corp: 22 exec/s 0 oom/timeout/crash: 0/0/0 time: 998s job: 67 dft_time: 0
INFO: fuzzed for 1014 seconds, wrapping up soon
INFO: exiting: 0 time: 1047s


$ cargo fuzz run fuzz_verify -j 4 -- -max_total_time=1000

#307: cov: 18818 ft: 12996 corp: 30 exec/s 0 oom/timeout/crash: 0/0/0 time: 915s job: 57 dft_time: 0
#314: cov: 18818 ft: 13023 corp: 32 exec/s 0 oom/timeout/crash: 0/0/0 time: 934s job: 58 dft_time: 0
#321: cov: 18818 ft: 13040 corp: 33 exec/s 0 oom/timeout/crash: 0/0/0 time: 945s job: 59 dft_time: 0
#328: cov: 18818 ft: 13063 corp: 34 exec/s 0 oom/timeout/crash: 0/0/0 time: 964s job: 60 dft_time: 0
#336: cov: 18818 ft: 13078 corp: 35 exec/s 0 oom/timeout/crash: 0/0/0 time: 998s job: 61 dft_time: 0
INFO: fuzzed for 1018 seconds, wrapping up soon
INFO: exiting: 0 time: 1031s
~~~

Coverage status of, for example, ml_dsa_44 is robust, see:

~~~
$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~
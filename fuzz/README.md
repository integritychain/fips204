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
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=3600  # run twice

#452: cov: 13276 ft: 9644 corp: 84 exec/s 0 oom/timeout/crash: 0/0/0 time: 509s job: 37 dft_time: 0
#483: cov: 13276 ft: 9651 corp: 86 exec/s 0 oom/timeout/crash: 0/0/0 time: 521s job: 38 dft_time: 0
#500: cov: 13276 ft: 9652 corp: 87 exec/s 0 oom/timeout/crash: 0/0/0 time: 527s job: 39 dft_time: 0
#518: cov: 13276 ft: 9652 corp: 87 exec/s 0 oom/timeout/crash: 0/0/0 time: 536s job: 40 dft_time: 0
#534: cov: 13276 ft: 9681 corp: 89 exec/s 0 oom/timeout/crash: 0/0/0 time: 557s job: 41 dft_time: 0
#553: cov: 13276 ft: 10255 corp: 92 exec/s 0 oom/timeout/crash: 0/0/0 time: 575s job: 42 dft_time: 0
~~~

Coverage status of ml_dsa_44 is robust, see:

~~~
$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~
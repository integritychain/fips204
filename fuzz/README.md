See <https://rust-fuzz.github.io/book/introduction.html>

~~~
$ cd fuzz  # this directory; you may need to install cargo fuzz
$ rustup default nightly
$ mkdir -p corpus/fuzz_all
$ dd if=/dev/zero bs=1 count=6292 > corpus/fuzz_all/seed0
$ for i in $(seq 1 2); do head -c 6292 </dev/urandom > corpus/fuzz_all/seed$i; done
$ dd if=/dev/zero bs=1 count=6292 | tr '\0x00' '\377' > corpus/fuzz_all/seed3
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=3600

#3086784: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 32989s job: 584 dft_time: 0
#3093638: cov: 6098 ft: 4465 corp: 256 exec/s 22 oom/timeout/crash: 0/0/0 time: 33064s job: 585 dft_time: 0
#3100594: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 33142s job: 586 dft_time: 0
#3107672: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 33212s job: 587 dft_time: 0
#3115218: cov: 6098 ft: 4465 corp: 256 exec/s 25 oom/timeout/crash: 0/0/0 time: 33290s job: 588 dft_time: 0
#3122208: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 33366s job: 589 dft_time: 0
#3129179: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 33443s job: 590 dft_time: 0
#3136367: cov: 6098 ft: 4465 corp: 256 exec/s 23 oom/timeout/crash: 0/0/0 time: 33514s job: 591 dft_time: 0
#3143903: cov: 6098 ft: 4465 corp: 256 exec/s 25 oom/timeout/crash: 0/0/0 time: 33592s job: 592 dft_time: 0
~~~

Now generate a coverage report...

~~~

$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~
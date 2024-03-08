See <https://rust-fuzz.github.io/book/introduction.html>

~~~
$ rustup default nightly
$ cd fuzz    # <this directory>
$ mkdir -p corpus/fuzz_all
$ head -c 6292 </dev/urandom > corpus/fuzz_all/seed1
$ cargo fuzz run fuzz_all -j 4 -- -max_total_time=300

(run twice)

INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 708871690
INFO: Loaded 1 modules   (39289 inline 8-bit counters): 39289 [0x56391a65e620, 0x56391a667f99), 
INFO: Loaded 1 PC tables (39289 PCs): 39289 [0x56391a667fa0,0x56391a701730), 
INFO: -fork=4: fuzzing in separate process(s)
INFO: -fork=4: 106 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork491405.dir
#375: cov: 3099 ft: 3099 corp: 106 exec/s 187 oom/timeout/crash: 0/0/0 time: 3s job: 1 dft_time: 0
... (new funcs) ...
#870: cov: 4821 ft: 3108 corp: 110 exec/s 165 oom/timeout/crash: 0/0/0 time: 4s job: 2 dft_time: 0
#1591: cov: 4823 ft: 3119 corp: 114 exec/s 180 oom/timeout/crash: 0/0/0 time: 5s job: 3 dft_time: 0
#2576: cov: 4826 ft: 3136 corp: 117 exec/s 197 oom/timeout/crash: 0/0/0 time: 6s job: 4 dft_time: 0
#3600: cov: 4827 ft: 3141 corp: 119 exec/s 170 oom/timeout/crash: 0/0/0 time: 10s job: 5 dft_time: 0
#4829: cov: 4828 ft: 3149 corp: 121 exec/s 175 oom/timeout/crash: 0/0/0 time: 12s job: 6 dft_time: 0
#6223: cov: 4829 ft: 3155 corp: 124 exec/s 174 oom/timeout/crash: 0/0/0 time: 14s job: 7 dft_time: 0
#7730: cov: 4829 ft: 3212 corp: 129 exec/s 167 oom/timeout/crash: 0/0/0 time: 16s job: 8 dft_time: 0
#9431: cov: 4830 ft: 3218 corp: 131 exec/s 170 oom/timeout/crash: 0/0/0 time: 20s job: 9 dft_time: 0
#11273: cov: 4831 ft: 3231 corp: 136 exec/s 167 oom/timeout/crash: 0/0/0 time: 23s job: 10 dft_time: 0
#13215: cov: 4831 ft: 3236 corp: 139 exec/s 161 oom/timeout/crash: 0/0/0 time: 26s job: 11 dft_time: 0
#15318: cov: 4831 ft: 3238 corp: 141 exec/s 161 oom/timeout/crash: 0/0/0 time: 29s job: 12 dft_time: 0
#17653: cov: 4831 ft: 3241 corp: 142 exec/s 166 oom/timeout/crash: 0/0/0 time: 35s job: 13 dft_time: 0
#20163: cov: 4831 ft: 3243 corp: 143 exec/s 167 oom/timeout/crash: 0/0/0 time: 38s job: 14 dft_time: 0
#22799: cov: 4831 ft: 3247 corp: 144 exec/s 164 oom/timeout/crash: 0/0/0 time: 42s job: 15 dft_time: 0
#25644: cov: 4831 ft: 3255 corp: 146 exec/s 167 oom/timeout/crash: 0/0/0 time: 47s job: 16 dft_time: 0
#28572: cov: 4831 ft: 3255 corp: 146 exec/s 162 oom/timeout/crash: 0/0/0 time: 53s job: 17 dft_time: 0
#31644: cov: 4831 ft: 3258 corp: 147 exec/s 161 oom/timeout/crash: 0/0/0 time: 58s job: 18 dft_time: 0
#34948: cov: 4831 ft: 3258 corp: 147 exec/s 165 oom/timeout/crash: 0/0/0 time: 63s job: 19 dft_time: 0
#38534: cov: 4831 ft: 3262 corp: 149 exec/s 170 oom/timeout/crash: 0/0/0 time: 68s job: 20 dft_time: 0
#42350: cov: 4831 ft: 3263 corp: 150 exec/s 173 oom/timeout/crash: 0/0/0 time: 76s job: 21 dft_time: 0
#45956: cov: 4831 ft: 3268 corp: 151 exec/s 156 oom/timeout/crash: 0/0/0 time: 81s job: 22 dft_time: 0
#50243: cov: 4831 ft: 3275 corp: 154 exec/s 178 oom/timeout/crash: 0/0/0 time: 87s job: 23 dft_time: 0
#54612: cov: 4831 ft: 3278 corp: 156 exec/s 174 oom/timeout/crash: 0/0/0 time: 93s job: 24 dft_time: 0
#59006: cov: 4831 ft: 3282 corp: 157 exec/s 169 oom/timeout/crash: 0/0/0 time: 102s job: 25 dft_time: 0
#63622: cov: 4831 ft: 3282 corp: 157 exec/s 170 oom/timeout/crash: 0/0/0 time: 109s job: 26 dft_time: 0
#68600: cov: 4831 ft: 3379 corp: 158 exec/s 177 oom/timeout/crash: 0/0/0 time: 116s job: 27 dft_time: 0
#73305: cov: 4831 ft: 3381 corp: 159 exec/s 162 oom/timeout/crash: 0/0/0 time: 123s job: 28 dft_time: 0
#78406: cov: 4831 ft: 3381 corp: 159 exec/s 170 oom/timeout/crash: 0/0/0 time: 132s job: 29 dft_time: 0
#83511: cov: 4831 ft: 3381 corp: 159 exec/s 164 oom/timeout/crash: 0/0/0 time: 140s job: 30 dft_time: 0
#88768: cov: 4831 ft: 3381 corp: 159 exec/s 164 oom/timeout/crash: 0/0/0 time: 149s job: 31 dft_time: 0
#94078: cov: 4831 ft: 3382 corp: 160 exec/s 160 oom/timeout/crash: 0/0/0 time: 157s job: 32 dft_time: 0
#99544: cov: 4831 ft: 3382 corp: 160 exec/s 160 oom/timeout/crash: 0/0/0 time: 167s job: 33 dft_time: 0
#105351: cov: 4831 ft: 3384 corp: 161 exec/s 165 oom/timeout/crash: 0/0/0 time: 176s job: 34 dft_time: 0
#111111: cov: 4831 ft: 3384 corp: 161 exec/s 160 oom/timeout/crash: 0/0/0 time: 185s job: 35 dft_time: 0
#117276: cov: 4831 ft: 3384 corp: 161 exec/s 166 oom/timeout/crash: 0/0/0 time: 194s job: 36 dft_time: 0
#123570: cov: 4831 ft: 3384 corp: 161 exec/s 165 oom/timeout/crash: 0/0/0 time: 205s job: 37 dft_time: 0
#130052: cov: 4831 ft: 3384 corp: 161 exec/s 166 oom/timeout/crash: 0/0/0 time: 215s job: 38 dft_time: 0
#137189: cov: 4831 ft: 3384 corp: 161 exec/s 178 oom/timeout/crash: 0/0/0 time: 226s job: 39 dft_time: 0
#144270: cov: 4831 ft: 3385 corp: 162 exec/s 172 oom/timeout/crash: 0/0/0 time: 236s job: 40 dft_time: 0
#151734: cov: 4831 ft: 3386 corp: 163 exec/s 177 oom/timeout/crash: 0/0/0 time: 248s job: 41 dft_time: 0
#158944: cov: 4831 ft: 3390 corp: 165 exec/s 167 oom/timeout/crash: 0/0/0 time: 259s job: 42 dft_time: 0
#166412: cov: 4831 ft: 3395 corp: 167 exec/s 169 oom/timeout/crash: 0/0/0 time: 270s job: 43 dft_time: 0
#173716: cov: 4831 ft: 3396 corp: 168 exec/s 162 oom/timeout/crash: 0/0/0 time: 281s job: 44 dft_time: 0
#181399: cov: 4831 ft: 3396 corp: 168 exec/s 167 oom/timeout/crash: 0/0/0 time: 294s job: 45 dft_time: 0
#189143: cov: 4831 ft: 3402 corp: 169 exec/s 164 oom/timeout/crash: 0/0/0 time: 306s job: 46 dft_time: 0
INFO: fuzzed for 307 seconds, wrapping up soon
INFO: exiting: 0 time: 307s
~~~

Now generate a coverage report...

~~~

$ cargo fuzz coverage fuzz_all

$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=./coverage/fuzz_all/coverage.profdata > index.html
~~~


~~~
$ rustup default nightly
$ head -c 6292 </dev/urandom > seed1
$ cargo fuzz run fuzz_all -j 4

INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1973874562
INFO: Loaded 1 modules   (33986 inline 8-bit counters): 33986 [0x55bac21089e0, 0x55bac2110ea2), 
INFO: Loaded 1 PC tables (33986 PCs): 33986 [0x55bac2110ea8,0x55bac2195ac8), 
INFO: -fork=4: fuzzing in separate process(s)
INFO: -fork=4: 118 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork320486.dir
#327: cov: 3130 ft: 3130 corp: 118 exec/s 163 oom/timeout/crash: 0/0/0 time: 5s job: 1 dft_time: 0
#785: cov: 4503 ft: 3130 corp: 118 exec/s 152 oom/timeout/crash: 0/0/0 time: 6s job: 2 dft_time: 0
#1404: cov: 4504 ft: 3140 corp: 120 exec/s 154 oom/timeout/crash: 0/0/0 time: 7s job: 3 dft_time: 0
#2173: cov: 4507 ft: 3147 corp: 122 exec/s 153 oom/timeout/crash: 0/0/0 time: 8s job: 4 dft_time: 0
#3145: cov: 4508 ft: 3155 corp: 123 exec/s 162 oom/timeout/crash: 0/0/0 time: 11s job: 5 dft_time: 0
#4313: cov: 4508 ft: 3157 corp: 125 exec/s 166 oom/timeout/crash: 0/0/0 time: 13s job: 6 dft_time: 0
#5703: cov: 4509 ft: 3169 corp: 129 exec/s 173 oom/timeout/crash: 0/0/0 time: 16s job: 7 dft_time: 0
#7240: cov: 4509 ft: 3169 corp: 129 exec/s 170 oom/timeout/crash: 0/0/0 time: 18s job: 8 dft_time: 0
#9004: cov: 4509 ft: 3169 corp: 129 exec/s 176 oom/timeout/crash: 0/0/0 time: 22s job: 9 dft_time: 0
#10897: cov: 4509 ft: 3170 corp: 130 exec/s 172 oom/timeout/crash: 0/0/0 time: 25s job: 10 dft_time: 0
#12934: cov: 4510 ft: 3186 corp: 134 exec/s 169 oom/timeout/crash: 0/0/0 time: 28s job: 11 dft_time: 0
#15217: cov: 4510 ft: 3186 corp: 134 exec/s 175 oom/timeout/crash: 0/0/0 time: 31s job: 12 dft_time: 0
#17627: cov: 4510 ft: 3186 corp: 134 exec/s 172 oom/timeout/crash: 0/0/0 time: 36s job: 13 dft_time: 0
#20175: cov: 4510 ft: 3191 corp: 137 exec/s 169 oom/timeout/crash: 0/0/0 time: 40s job: 14 dft_time: 0
#22838: cov: 4510 ft: 3191 corp: 137 exec/s 166 oom/timeout/crash: 0/0/0 time: 44s job: 15 dft_time: 0
#25656: cov: 4510 ft: 3194 corp: 138 exec/s 165 oom/timeout/crash: 0/0/0 time: 48s job: 16 dft_time: 0
#28572: cov: 4510 ft: 3201 corp: 140 exec/s 162 oom/timeout/crash: 0/0/0 time: 54s job: 17 dft_time: 0
#31705: cov: 4510 ft: 3210 corp: 143 exec/s 164 oom/timeout/crash: 0/0/0 time: 60s job: 18 dft_time: 0
#35087: cov: 4510 ft: 3210 corp: 143 exec/s 169 oom/timeout/crash: 0/0/0 time: 65s job: 19 dft_time: 0
#38565: cov: 4510 ft: 3222 corp: 145 exec/s 165 oom/timeout/crash: 0/0/0 time: 70s job: 20 dft_time: 0
...
~~~
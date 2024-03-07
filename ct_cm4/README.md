An example for the STM Discovery Board -- <https://docs.rust-embedded.org/discovery/f3discovery/index.html>

This was derived from code in the FIPS 203 crate and isn't working just yet. 
This is likely due to a too-large stack frame; keyGen itself is approx >32kB
in the ideal case, measured to 67k(opt-level=3/"z"/"s") vs 40kB of SRAM in MCU.
See pages 15 and 53 of <https://www.st.com/content/ccc/resource/technical/document/datasheet/f2/1f/e1/41/ef/59/4d/50/DM00058181.pdf/files/DM00058181.pdf/jcr:content/translations/en.DM00058181.pdf>

One-off setup:

~~~
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools-preview
~~~

You will need to be running with two windows in parallel.

1. In the first window:

   ~~~
   $ cd ct_cm4   # <here>
   $ cargo build --target thumbv7em-none-eabihf
   $ cargo readobj --target thumbv7em-none-eabihf --bin ct_cm4-fips204 -- --file-header  # double-checks built object
   $ cargo size --bin ct_cm4-fips204 --release -- -A
   ~~~

2. In the second window:

   ~~~
   $ cd /tmp && openocd -f interface/stlink-v2-1.cfg -f target/stm32f3x.cfg
   ~~~

3. Back to the first window:

   ~~~
   $ cargo run

   then:
      layout src
      break k_pke.rs:29
      continue
      s
   ~~~

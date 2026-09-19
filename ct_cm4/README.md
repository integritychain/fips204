An example for the Microbit v2 Board -- <https://docs.rust-embedded.org/discovery/microbit/index.html>

This example demonstrates the "firmware signature verification" scenario with a cycle count measurement. 
See the link above for tooling setup.

Requires the same MSRV as the main crate (**Rust 1.85+**). A direct pin on `fixed = "=1.30.0"`
keeps the `microbit-v2` dependency graph buildable at that MSRV.

 ~~~
 $ cd ct_cm4   # <here>
 $ cargo embed
 ~~~

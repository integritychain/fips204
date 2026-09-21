# [IntegrityChain]: FIPS 204 Module-Lattice-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 204] Module-Lattice-Based Digital Signature Standard written in pure/safe Rust for server, desktop, browser and
embedded applications. The source repository includes examples demonstrating benchmarking, an embedded target,
constant-time statistical measurements, fuzzing, WASM execution, a C FFI shared library, and robust test coverage.

This crate implements [the FIPS 204 **released** standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) in
pure Rust with minimal and mainstream dependencies, and without any unsafe code. All three security parameter sets are
fully functional and tested. The implementation's key- and signature-generation functionality operates in constant-time,
does not require the standard library, e.g. `#[no_std]`, has no heap allocations, e.g. no `alloc` needed, and exposes
the `RNG` so it is suitable for the full range of applications down to the bare-metal. The API is stabilized and the
code is heavily biased towards safety and correctness; further performance optimizations may be implemented over time.
This crate will quickly follow any changes related to FIPS 204 as they become available.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
// Use the desired target parameter set.
# use std::error::Error;
#
# fn main() -> Result<(), Box<dyn Error>> { 
# #[cfg(all(feature = "ml-dsa-44", feature = "default-rng"))] { 
use fips204::ml_dsa_44; // Could also be ml_dsa_65 or ml_dsa_87. 
use fips204::traits::{SerDes, Signer, Verifier};
let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate key pair and signature
let (pk1, sk) = ml_dsa_44::try_keygen()?;  // Generate both public and secret keys
let sig = sk.try_sign(&message, &[])?;  // Use the secret key to generate a message signature

// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv)?;
let v = pk2.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
assert!(v);
    
// Note that the last argument to sign() and verify() is the (NIST specified) context
// value which is typically empty for basic signature generation and verification.
# }
# Ok(())
# }
~~~

The Rust [Documentation][docs-link] lives under each **Module** corresponding to the desired
[security parameter][docs-modules].

## Notes

* This crate is fully functional and corresponds to the final released FIPS 204 (August 13, 2024).
* NIST ACVP test vectors (keyGen / sigGen / sigVer) are exercised against the public API,
  including external interface and HashML-DSA for the digests enumerated in `Ph`
  (`SHA2-256`, `SHA2-512`, `SHAKE-128`).
* An optional `ffi` workspace member builds `libfips204`, a C ABI shared library for the
  pure ML-DSA external interfaces (see [`ffi/README.md`](ffi/README.md)). HashML-DSA is not
  yet exported through the FFI.
* A WASM browser demo lives under [`wasm/`](wasm/) (see [`wasm/README.md`](wasm/README.md)).
* RNG integration uses **`rand_core` 0.6**. The default features enable
  `default-rng` plus all three parameter sets. That OS RNG
  path is for hosted environments; it will **not** compile on bare-metal targets
  that lack a `getrandom` backend (for example `thumbv7em-none-eabi`). So for
  embedded / `no_std` builds, disable defaults and pick the sets you need, then
  supply entropy via seeds or `*_with_rng`:
  `fips204 = { version = "0.5", default-features = false, features = ["ml-dsa-44"] }`
  (see also [`ct_cm4/`](ct_cm4/)). Custom generators must implement `TryCryptoRng`
  (re-exported from this crate). `OsRng` is fallible-only on this line; prefer
  seed-based APIs or handle `try_fill_bytes` errors when driving the OS RNG yourself.
* Constant-time assurances target the source-code level only, with manual confirmation via
  review/inspection, the embedded target, and the `dudect` dynamic/statistical measurements.
* Note that FIPS 204 places specific requirements on randomness per section 3.6.1, hence the exposed `RNG`.
* Requires Rust **1.85** or higher (aligned with Debian stable / trixie). The minimum
  supported Rust version may be changed in the future, but it will be done with a minor
  version bump once the major version is larger than 0.
* All on-by-default features of this library are covered by `SemVer`.
* Until it matures further, the FIPS 204 standard and this software should be considered experimental.

## License

Contents are licensed under either the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as 
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/fips204
[crate-link]: https://crates.io/crates/fips204
[docs-image]: https://docs.rs/fips204/badge.svg
[docs-link]: https://docs.rs/fips204/
[docs-modules]: https://docs.rs/fips204/latest/fips204/#modules
[build-image]: https://github.com/integritychain/fips204/workflows/test/badge.svg
[build-link]: https://github.com/integritychain/fips204/actions?query=workflow%3Atest
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

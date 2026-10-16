# [IntegrityChain]: FIPS 204 Module-Lattice-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 204] Module-Lattice-Based Digital Signature Standard written in pure Rust for server, desktop, browser and
embedded applications. The source repository includes examples demonstrating benchmarking, code provenance, an
embedded target, constant-time statistical measurements, a fuzzing harness, WASM execution, a C FFI shared library and
Python bindings.

This crate implements the released FIPS 204 standard in pure Rust with minimal and mainstream dependencies, and without
any unsafe code. All three security parameter sets are fully functional and tested. Key generation and signing are
constant-time within each attempt: they do not branch on secret data, though rejection sampling makes the number of
attempts vary. The crate does not require the standard library (it is `#![no_std]`), makes no heap allocations (no
`alloc` needed), and exposes the `RNG`, so it suits the full range of applications from server down to bare metal. The
API is stabilized, and the code is heavily biased towards safety and correctness.

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
let v = pk2.verify(&msg_recv, &sig_recv, &[]); // Use the public key to verify the message signature
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
* Constant-time: within one attempt, key generation and signing do not branch on secret data. Two
  steps use rejection sampling, so their number of iterations varies: sampling the secret vectors
  (`ExpandS`), and the signing loop, which FIPS 204 restarts until a signature meets its bounds.
  Signing gives up with an error after 814 attempts (FIPS 204 Appendix C), which a valid key
  reaches with probability about 2^−256 but a malformed private key can reach every time.
  Expanding the matrix Â from the seed ρ varies too, but ρ is public, carried in the public key.
  Checked by source review and by the [`dudect`][dudect-readme] measurements. The claim is at
  the source level: the compiler and CPU are trusted not to add secret-dependent timing, and the
  caller's RNG is outside it. Verify uses only public data and makes no constant-time claim.
* FIPS 204 places specific requirements on randomness (section 3.6.1), hence the exposed `RNG`. RNG
  integration uses **`rand_core` 0.6**: custom generators implement `CryptoRngCore` (`CryptoRng` +
  `RngCore`), which this crate re-exports along with `RngError`. Key generation and signing call
  `try_fill_bytes`, so handle its error or use the seed-based functions.
* The default features enable `default-rng` plus all three parameter sets. That OS RNG path is for
  hosted environments; it will **not** compile on bare-metal targets that lack a `getrandom`
  backend (for example `thumbv7em-none-eabi`). Embedded builds use `default-features = false`,
  the parameter-set feature they need, and the seed-based functions or `*_with_rng`, as in
  [`ct_cm4/`][ct_cm4-dir]:
  `fips204 = { version = "0.5", default-features = false, features = ["ml-dsa-44"] }`.
* `try_hash_sign` and `hash_verify` (HashML-DSA) take a precomputed digest and a DER-encoded OID
  (`pre_hash` lists the NIST CSOR encodings). The library does not hash the message. For a
  `pre_hash` OID the digest must have that function's output length (32 bytes for SHAKE128, 64
  for SHAKE256), so passing the message by mistake is an error. Any other OID must be
  DER-encoded and takes a digest of up to 1024 bytes.
* Test vectors: the NIST ACVP keyGen, sigGen and sigVer vectors (including HashML-DSA and private
  keys given as seeds), the C2SP Wycheproof ML-DSA vectors and the CCTV accumulated tests run in
  the test suite, and the C and Python bindings apply the ACVP files through the C ABI. The vector
  files stay in the repository; the published crate omits them.
* A C shared library (`libfips204`) for the external ML-DSA and HashML-DSA interfaces, with Python
  bindings, and a WASM browser demo, are described in [`ffi/README.md`][ffi-readme] and
  [`wasm/README.md`][wasm-readme].
* Requires Rust **1.85** or higher (Debian stable, trixie). The minimum supported Rust version may
  change in the future, but only with a minor version bump (once the major version is above 0).
* All on-by-default features of this library are covered by `SemVer`.

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

[ct_cm4-dir]: https://github.com/integritychain/fips204/tree/main/ct_cm4
[dudect-readme]: https://github.com/integritychain/fips204/blob/main/dudect/README.md
[ffi-readme]: https://github.com/integritychain/fips204/blob/main/ffi/README.md
[wasm-readme]: https://github.com/integritychain/fips204/blob/main/wasm/README.md
[IntegrityChain]: https://github.com/integritychain/
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

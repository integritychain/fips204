# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (in progress)

### Migration from 0.4.x
- Not API-compatible with 0.4.6. Depend on `fips204 = "0.5"`.
- MSRV is **1.85**.
- `Ph` is gone. `hash_sign` and `hash_verify` take a precomputed digest and a DER-encoded OID (`pre_hash`). This crate does not hash the message. An empty OID or a digest longer than 1024 bytes is an error on sign and a failed verify.
- RNG stays `rand_core` 0.6. `CryptoRng`, `RngCore`, and `RngError` are re-exported. There is no `TryCryptoRng`.
- Default features enable the OS RNG and all three parameter sets. That does not build on bare metal. Use `default-features = false`, one `ml-dsa-*` feature, and seeds or `*_with_rng`.

### Added
- `libfips204` for ML-DSA and HashML-DSA (44/65/87), and Python bindings in `ffi/python`. Thanks to @dkg.

### Changed
- Release builds use opt-level 3.
- The constant-time claim covers one attempt. Rejection sampling may repeat. Within an attempt, key generation and signing do not branch on secret data.

### Removed
- Temporary `_internal_sign` and `_internal_verify`.

### Fixed
- The `ml-dsa-65` and `ml-dsa-87` features now gate their modules. Before, `ml_dsa_65` and `ml_dsa_87` were always compiled. A build that uses either module must enable its feature.
- `ffi/fips204.h` compiles as C++ (C++11 and later). The header has an `extern "C"` block for C++ callers, but parameters named `private` and `public` are C++ keywords, so every C++ build failed. They are now `private_key` and `public_key`, as in `fips205.h`. The inline `*_deterministic` wrappers zero their seed with `{ { 0 } }`. The designated initializer they used before is C++20 only, and a `-pedantic -Werror` build rejected it. Parameter names are not part of the C ABI, so C callers and the shared library are unchanged.
- In the Rust FFI, `ml_dsa_*_get_public_key` borrows the private key as `&`, matching the `const` pointer in `fips204.h`. It never writes the key. The old `&mut` claimed exclusive write access that a caller passing a `const` key does not grant.
- The seed parameter of `ml_dsa_*_keygen_from_seed` in `fips204.h` is `seed`, not `d_z`. `d_z` named the ML-KEM seed (`d || z`), but ML-DSA key generation takes a single 32-byte seed, ξ.

## 0.4.6 (2024-12-21)

- Added support deterministic signatures via `_seed`
- Trivial typo on signature return error doc

## 0.4.5 (2024-11-08)

- Bug fix in Hash-ML-DSA - thank you @codespree
- Two new fuzzers with tons of new coverage: fuzz_sign and fuzz_verify

## 0.4.4 (2024-10-29)

- Significant shrink of required stack size
- Internal-only refactoring, clean-up and polishing

## 0.4.3 (2024-10-16)

- Adapted ExpandedPrivateKey into PrivateKey and ExpandedPublicKey into PublicKey, removed the former(s)
- Internal revision to align comments with released spec; added try_hash_sign (using OS rng)
- Revisit/revise supporting benchmarks, embedded target, dudect, fuzz and wasm functionality 
- Fixed a bug in verify relating to non-empty contexts; asserts on all doctests

## 0.4.2 (2024-10-05)

- Fixed size of SHAKE128 digest in `hash_message()` 
- Added sk.get_public_key()


## 0.4.1 (2024-09-30)

- Now exports the pre-hash function enum


## 0.4.0 (2024-09-29)

- Now aligned with **released** FIPS 204 including hash sig/verif and keygen with seed.


## 0.2.2 (2024-08-02)

- Bug fix to debug_assert in `power2round` and t_not_reduced in `keygen`; thank you @skilo-sh !! 


## 0.2.1 (2024-06-19)

- Internal revision based on review 2 feedback
- API: try_verify() -> verify() change to prevent usage mistakes


## 0.2.0 (2024-05-25)

- Reworked for constant-time key generation and signature. 
  This necessitated adapting the primary API (removing suffixes).
- Significant internal refinement and increased performance.


## 0.1.2 (2024-05-06)

- Significant internal refinement and increased performance.


## 0.1.1 (2024-03-08)

- Extensive internal refinement.
- Rework of expanded keys (in place of precomputes).
- Benchmarking, constant time checks, embedded sample, fuzz testing, wasm example.


## 0.1.0 (2024-01-01)

- Initial release

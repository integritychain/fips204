# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (in progress)

### Migration from 0.4.x
- Bump the dependency to `fips204 = "0.5"` (this release is **not** API-compatible with
  crates.io `0.4.6`).
- Replace `CryptoRngCore` bounds with `TryCryptoRng` (re-exported from `fips204`).
- Bare-metal / `no_std`: use `default-features = false` plus the desired `ml-dsa-*`
  feature(s); default features pull an OS RNG backend that will not build on many
  embedded targets.
- MSRV is now **1.85**.

### Added
- `ffi` workspace member (`fips204-ffi`) producing `libfips204`, a C shared library for
  pure ML-DSA keygen / sign / verify across ML-DSA-44/65/87 (HashML-DSA not yet exported
  via FFI); thank you @dkg

### Fixed
- `Signer::get_public_key` doctest no longer requires `default-rng` (uses
  `keygen_from_seed`; thank you @dkg for the earlier feature-subset report)
- RustSec advisories: bump Criterion to 0.5 (drops unmaintained/unsound `atty`);
  replace unmaintained `paste` with `pastey` in `fips204-ffi`
- Clippy pedantic cleanups for current stable (`needless_for_each`,
  `unnecessary_semicolon`, `large_stack_arrays` allow on the K=255 test, etc.); CI
  `clippy` job now installs `dtolnay/rust-toolchain@stable` with the clippy component
- CI `cargo_deny`: bump `EmbarkStudios/cargo-deny-action` to v2 (CVSS 4.0 advisory
  DB support); refresh `deny.toml` `[graph]`/`[output]` layout
- CI `cargo_outdated`: exclude `rand_core` from Latest probing (`-x rand_core`) so the
  job does not fail while we stay on the 0.6 line
- WASM demo: refresh npm toolchain (`copy-webpack-plugin` 14, `webpack-cli` 7,
  `webpack-dev-server` 6) clearing Dependabot `serialize-javascript` / `uuid`
  advisories; bump `wasm-bindgen` / `wasm-bindgen-test`; fix `fips204` path dep to `..`
  (was clone-name-fragile `../../fips204`); rewrite `wasm/README.md` and
  `wasm/www/README.md` (drop stale create-wasm-app/Travis text; document Node/npm,
  layout, and optional `getrandom_backend="wasm_js"` for OS RNG); rename
  `wasm/www` npm package to `fips204-wasm-www`; point the demo page at the final
  FIPS 204 PDF §3.6.1 (was draft IPD §3.5.1)
- `ct_cm4`: pin `fixed = "=1.30.0"` so the Microbit sample resolves on MSRV 1.85
  (`fixed` 1.31+ needs rustc 1.93 via `microbit-v2`)
- `KeyGen::keygen_from_seed` doctest no longer requires `default-rng` (uses
  `try_sign_with_seed`; drop stray `///` / `OsRng` from the example)
- Rustdoc polish in `traits` / algorithm map: grammar fixes, Dilithium link
  punctuation, `HashML-DSA.Verify` takes `pk` (not `sk`), brief `traits` module docs;
  `ml_dsa_65` / `ml_dsa_87` module docs link their own types (were copy-pasted as
  `ml_dsa_44`)

### Changed
- Crate and sample versions are **0.5.0** (`fips204`, `fips204-ffi`, `wasm`, `ct_cm4`,
  `dudect`, `fuzz`)
- Updated NIST ACVP test vectors and aligned keyGen / sigGen / sigVer tests with the
  public external API (including HashML-DSA for digests in `Ph`); thank you @dkg
- Raised MSRV to **1.85** (Debian stable / trixie); CI MSRV jobs updated accordingly;
  NIST keyGen tests use `TryInto` for seed arrays; pin `textwrap = "=0.16.2"` so
  Criterion stays buildable without a checked-in `Cargo.lock`
- Document that default features (including `default-rng` / `os_rng`) are for hosted
  targets; bare-metal / `no_std` consumers should use `--no-default-features` plus
  the desired `ml-dsa-*` feature(s) and seed/`*_with_rng` APIs (see `ct_cm4/`)
- Drop “(draft)” from sample crate descriptions; point GitHub README security-parameter
  link at docs.rs `#modules` (not a broken in-page anchor); clarify `KeyGen`
  associated-type docs (drop stale “expanded key” wording); fix incomplete
  `try_hash_sign_with_seed` doc sentence
- FFI polish: include `<stddef.h>` in `fips204.h`; create a local `libfips204.so.0`
  symlink in the FFI test Makefile for Linux in-tree `make check`; expand
  `ffi/README.md` with header/`SONAME`/linking/`pkg-config` notes for C consumers
  (Python bindings are not in-tree yet)

### Removed
- Temporary public `_internal_sign` / `_internal_verify` helpers and the NIST-only
  internal codepath in `sign_internal` / `verify_internal` (thank you @dkg)

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

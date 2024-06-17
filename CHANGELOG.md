# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2024-06-18)

- Internal rework based on review 2 feedback
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

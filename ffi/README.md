# C Shared Object for ML-DSA

This crate provides a shared object (dynamically-linked library) using standard C FFI ABI that provides a functional implementation of ML-DSA.

The goals of this implementation are:

- simplicity
- correctness
- caller deals only with serialized objects
- no library-specific memory management (caller manages all objects)
- no internal state held by the library between calls
- minimal symbol visibility
- stable API/ABI

security-related goals:

- constant-time operations
- clean library RAM (objects should be zeroed out of any library-allocated memory before function exit)

non-goals are:

- speed
- efficiency
- size

# Outstanding work

- better internal error handling
- more testing
- reduce symbol visibility in shared object
- export hash_sign and hash_verify
- Python bindings (planned; not in-tree yet)


# Paths considered but discarded

- Autogenerate stable C headers (e.g. with cbindgen); manually-crafted headers are probably fine, given the simplicity of the API/ABI


# Quick start

~~~
$ cd ffi   # this directory
$ cargo build -p fips204-ffi
$ (cd tests && make)
~~~

The C smoke tests under `tests/` exercise keygen, hedged and deterministic signing, verification,
and `get_public_key` for ML-DSA-44/65/87 against the locally built `libfips204`.

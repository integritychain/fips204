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
- testing!
- reduce symbol visibility in shared object

# Paths considered but discarded

- Autogenerate stable C headers (e.g. with cbindgen); manually-crafted headers are probably fine, given the simplicity of the API/ABI


# Quick start

~~~
$ cd ffi   # this directory
$ cargo build
$ (cd tests && make)
$ cd python
$ python3
>>> from fips204 import ML_DSA_44
>>> 
>>> (public_key, private_key) = ML_DSA_44.keygen()
>>> msg = b'this is the message'
>>> sig = private_key.sign(msg)
>>> assert(public_key.verify(sig, msg)
~~~

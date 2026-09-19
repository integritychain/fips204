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


# Quick start (in-tree smoke tests)

~~~
$ cd ffi   # this directory
$ cargo build -p fips204-ffi
$ (cd tests && make)
~~~

The C smoke tests under `tests/` exercise keygen, hedged and deterministic signing, verification,
and `get_public_key` for ML-DSA-44/65/87 against the locally built `libfips204`.

If the library and headers are already installed system-wide, you can instead run:

~~~
$ (cd tests && make AS_INSTALLED=true)
~~~


# Header

Ship / include [`fips204.h`](fips204.h) with your application. It is hand-maintained (not
cbindgen). It includes `<stddef.h>` and `<stdint.h>` for portable size/integer types.

Compile C callers with something like `-I/path/to/ffi` (the directory that contains
`fips204.h`).


# Shared library names (Linux ELF SONAME)

`cargo build -p fips204-ffi` produces a cdylib named **`libfips204.so`** (or
`libfips204.dylib` on macOS) under `target/debug` or `target/release`.

On Linux (and other ELF targets), [`build.rs`](build.rs) also sets the ELF **SONAME** to
**`libfips204.so.0`** (major version from the crate). That means:

| Artifact | Role |
|---|---|
| `libfips204.so` | Link name Cargo emits; use `-lfips204` at link time |
| `libfips204.so.0` | Runtime name the dynamic loader looks up (SONAME) |

After install, distributors typically provide both: the versioned file (or symlink) that
matches the SONAME, plus an unversioned `libfips204.so` symlink for the linker.

For **in-tree** tests, `tests/Makefile` creates a local `libfips204.so.0` → `libfips204.so`
symlink next to Cargo’s output so `LD_LIBRARY_PATH` runs succeed without a full install.
If you link your own binary against a raw `target/*/libfips204.so` on Linux, either:

- create the same `libfips204.so.0` symlink beside it, or
- install the library with a packaging layout that provides the SONAME, or
- set an appropriate rpath / use `LD_LIBRARY_PATH` **and** ensure `libfips204.so.0`
  resolves (a bare `libfips204.so` alone is not enough when SONAME is `.so.0`).

On **macOS**, `build.rs` sets the install name to `@rpath/libfips204.dylib` instead of
an ELF-style SONAME; the Makefile does not need a `.so.0` symlink there.


# Linking a C program (local build)

Example against a debug build from the repo root:

~~~
$ cargo build -p fips204-ffi
$ cc -o myapp myapp.c \
    -Iffi \
    -L target/debug -Wl,-rpath,$PWD/target/debug \
    -lfips204
# Linux: ensure runtime SONAME resolves, e.g.:
$ ln -sfn libfips204.so target/debug/libfips204.so.0
$ ./myapp
~~~


# pkg-config

`build.rs` writes a minimal `fips204.pc` into Cargo’s `OUT_DIR` (not into `target/debug`
by itself). It currently only declares `Libs: -lfips204` (no `Cflags` include path).
Treat it as a starting point for packagers; you will still need to install `fips204.h`
and set `-I` / `Cflags` appropriately for your layout.

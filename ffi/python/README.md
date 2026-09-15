# `fips204` Python module

This Python module provides an implementation of FIPS 204, the
Module-Lattice-based Digital Signature Standard.

The underlying mechanism is intended to offer "post-quantum"
data integrity, authenticity, and non-repudiation.

## Example

The following example shows using the standard ML-DSA algorithm to
sign a message:

```
from fips204 import ML_DSA_65

(public_key, private_key) = ML_DSA_65.keygen()
message = b"this is a test"
context = b""
sig = private_key.sign(message, context)
assert(public_key.verify(sig, message, context))
```

Key generation can also be done deterministically, by passing a
`SEED_SIZE`-byte seed to `keygen`:

```
from fips204 import ML_DSA_65, Seed

seed1 = Seed()  # Generate a random seed
(pub, priv) = ML_DSA_65.keygen(seed1)

seed2 = Seed(b'\x00'*ML_DSA_65.SEED_SIZE)  # This seed is clearly not a secret!
(pub, priv) = ML_DSA_65.keygen(seed2)
```

public keys, private keys, and seeds can all
be serialized by accessing them as `bytes`, and deserialized by
initializing them with the appropriate size bytes object.

A signature itself is already just a bytes object.

A serialization example:

```
from fips204 import ML_DSA_65, Seed

seed = Seed()
(pub,priv) = ML_DSA_65.keygen(seed)
with open('pub.bin', 'wb') as f:
    f.write(bytes(pub))
with open('priv.bin', 'wb') as f:
    f.write(bytes(priv))
with open('seed.bin', 'wb') as f:
    f.write(bytes(seed))
```

A deserialization example, followed by use:

```
import fips204

with open('priv.bin', 'b') as f:
    privdata = f.read()

context = b'abc'
priv = fips204.PrivateKey(pubdata)
with open('msg', 'rb') as m:
    with open ('msg.sig', 'wb') as s:
        s.write(priv.sign(m.read(), context)
```

The expected sizes (in bytes) of the different objects in each
parameter set can be accessed with `PUBKEY_SIZE`, `PRIVKEY_SIZE`, `SIG_SIZE`,
`SEED_SIZE`:

```
from fips204 import ML_DSA_65

print(f"ML-DSA-65 Signature size (in bytes) is {ML_DSA_65.SIG_SIZE}")
```

## Implementation Notes

This is a wrapper around libfips204, built from the Rust fips204-ffi crate.

If that library is not installed in the expected path for libraries on
your system, any attempt to use this module will fail.

This module should have reasonable type annotations and docstrings for
the public interface.  If you discover a problem with type
annotations, or see a way that this kind of documentation could be
improved, please report it!

## See Also

- https://doi.org/10.6028/NIST.FIPS.204
- https://github.com/integritychain/fips204

## Bug Reporting

Please report issues at https://github.com/integritychain/fips204/issues

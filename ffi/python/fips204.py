"""FIPS 204 (ML-DSA) Asymmetric Post-Quantum Digital Signatures

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
from fips204 import ML_DSA_65, seed

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
"""

from __future__ import annotations

"""__version__ should track package.version from  ../Cargo.toml"""
__version__ = "0.4.6"
__author__ = "Daniel Kahn Gillmor <dkg@fifthhorseman.net>"
__all__ = [
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
    "PublicKey",
    "PrivateKey",
    "Seed",
    "HashOID",
]

import ctypes
import ctypes.util
import enum
import secrets
from typing import Tuple, Dict, Any, Union, Optional
from abc import ABC
import sys
from os import path, environ
from enum import Enum


class HashOID(Enum):
    """Convenience for fips204.PrivateKey.hash_sign() fips204.PublicKey.hash_verify()

    Both of these functions need to take an identifier for the digest algorithm used.
    The identifier is passed in the form of a DER-encoded OID.

    To use a digest algorithm not encoded here, pass a raw bytes object instead.
    """

    SHA2_224 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04"
    SHA2_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    SHA2_384 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02"
    SHA2_512 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
    SHA2_512_224 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05"
    SHA2_512_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06"
    SHA3_224 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07"
    SHA3_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08"
    SHA3_384 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09"
    SHA3_512 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a"
    SHAKE_128 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b"
    SHAKE_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c"


# allow hyphens instead of underscores when looking up as a dict:
for h in HashOID:
    rep = h.name.replace("_", "-")
    if rep != h.name:
        h._add_alias_(rep)
# add common aliases for SHA2 variants:
HashOID.SHA2_224._add_alias_("SHA224")
HashOID.SHA2_256._add_alias_("SHA256")
HashOID.SHA2_384._add_alias_("SHA384")
HashOID.SHA2_512._add_alias_("SHA512")
HashOID.SHA2_512_224._add_alias_("SHA512/224")
HashOID.SHA2_512_256._add_alias_("SHA512/256")
HashOID.SHA2_512_224._add_alias_("SHA2-512/224")
HashOID.SHA2_512_256._add_alias_("SHA2-512/256")


class _Seed(ctypes.Structure):
    _fields_ = [("data", ctypes.c_uint8 * 32)]


class Err(enum.IntEnum):
    OK = 0
    NULL_PTR_ERROR = 1
    SERIALIZATION_ERROR = 2
    DESERIALIZATION_ERROR = 3
    KEYGEN_ERROR = 4
    SIGN_ERROR = 5
    VERIFICATION_ERROR = 6
    VERIFICATION_FAILURE = 7


class Seed:
    """ML-DSA Seed

    This seed can be used to generate an ML-DSA keypair
    """

    def __init__(self, data: Optional[bytes] = None) -> None:
        """If initialized with None, the seed will be randomly populated."""
        self._seed = _Seed()
        if data is None:
            # FIXME: perhaps use ml_dsa_populate_seed instead?
            data = secrets.token_bytes(len(self._seed.data))
        if len(data) != len(self._seed.data):
            raise ValueError(
                f"Expected {len(self._seed.data)} bytes, " f"got {len(data)}."
            )
        for i in range(len(data)):
            self._seed.data[i] = data[i]

    def __repr__(self) -> str:
        return "<ML-DSA Seed>"

    def __bytes__(self) -> bytes:
        return bytes(self._seed.data)

    def keygen(self, strength: int) -> Tuple[PublicKey, PrivateKey]:
        for kt in ML_DSA_44, ML_DSA_65, ML_DSA_87:
            if kt._strength == strength:
                return kt.keygen(self)
        raise Exception(f"Unknown strength: {strength}, must be 44, 65, or 87.")


class PublicKey:
    """ML-DSA Public Key

    Serialize this object by asking for it as `bytes`.

    Verify a signature by calling verify() on this, passing the
    signature, the message, and an explicit context.

    """

    def __init__(self, data: Union[bytes, int]) -> None:
        """Create ML-DSA Public Key from bytes (or strength level)."""
        if isinstance(data, bytes):
            self._strength = _ML_DSA.strength_from_length("PUBKEY_SIZE", len(data))
        elif isinstance(data, int):
            self._strength = data
        else:
            raise Exception(
                "Initialize ML-DSA Public Key with "
                f"bytes or a strength level, not {type(data)}"
            )
        self._ffi = _ML_DSA.strength(self._strength)
        self._pubkey = self._ffi["PublicKey"]()
        if isinstance(data, bytes):
            self._set(data)

    def __repr__(self) -> str:
        return f"<ML-DSA-{self._strength} Public Key>"

    def __bytes__(self) -> bytes:
        return bytes(self._pubkey.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._pubkey.data):
            raise ValueError(
                f"Expected {len(self._pubkey.data)} bytes, " f"got {len(data)}"
            )
        for i in range(len(data)):
            self._pubkey.data[i] = data[i]

    def verify(self, sig: bytes, message: bytes, context: bytes = b"") -> bool:
        """Verify a signature over a given message."""
        if not isinstance(sig, bytes):
            raise TypeError(
                f"{self}.verify wants a signature of type bytes, got {type(sig)}"
            )
        if not isinstance(message, bytes):
            raise TypeError(
                f"{self}.verify wants a signature of type bytes, got {type(message)}"
            )
        if not isinstance(context, bytes):
            raise TypeError(
                f"{self}.verify wants a context of type bytes, got {type(context)}"
            )
        sig_param = self._ffi["Signature"]()
        if len(sig) != len(sig_param.data):
            raise ValueError(
                f"{self} expects a signature of {len(sig_param.data)} bytes, got {len(sig)} bytes"
            )
        for i in range(len(sig_param.data)):
            sig_param.data[i] = sig[i]
        ret = Err(
            self._ffi["verify"](
                ctypes.byref(self._pubkey),
                ctypes.byref(sig_param),
                ctypes.cast(ctypes.c_char_p(message), ctypes.POINTER(ctypes.c_uint8)),
                len(message),
                ctypes.cast(ctypes.c_char_p(context), ctypes.POINTER(ctypes.c_uint8)),
                len(context),
            )
        )
        if ret not in {Err.OK, Err.VERIFICATION_FAILURE}:
            raise Exception(
                f"ml_dsa_{self._strength}_verify() " f"returned {ret} ({ret.name})"
            )
        return ret == Err.OK

    def hash_verify(
        self,
        sig: bytes,
        digest: bytes,
        hashoid: Union[bytes, HashOID],
        context: bytes = b"",
    ) -> bool:
        """Verify a signature over the digest of a message.

        Pass this function the digest of the message, not the message itself.

        The `hashoid` parameter is a DER-encoded OID that identifies the hash algorithm used.
        As a convenience, fips204.HashOID contains a list of DER-encoded OIDs of common digest algorithms.
        """
        if not isinstance(sig, bytes):
            raise TypeError(
                f"{self}.hash_verify wants a signature of type bytes, got {type(sig)}"
            )
        if not isinstance(digest, bytes):
            raise TypeError(
                f"{self}.hash_verify wants a digest of type bytes, got {type(digest)}"
            )
        if not isinstance(context, bytes):
            raise TypeError(
                f"{self}.hash_verify wants a context of type bytes, got {type(context)}"
            )
        if isinstance(hashoid, HashOID):
            hashoid = hashoid.value
        if not isinstance(hashoid, bytes):
            raise TypeError(
                f"{self}.hash_verify wants a hashoid of type bytes or HashOID, got {type(hashoid)}"
            )
        sig_param = self._ffi["Signature"]()
        if len(sig) != len(sig_param.data):
            raise ValueError(
                f"{self} expects a signature of {len(sig_param.data)} bytes, got {len(sig)} bytes"
            )
        for i in range(len(sig_param.data)):
            sig_param.data[i] = sig[i]
        ret = Err(
            self._ffi["hash_verify"](
                ctypes.byref(self._pubkey),
                ctypes.byref(sig_param),
                ctypes.cast(ctypes.c_char_p(digest), ctypes.POINTER(ctypes.c_uint8)),
                len(digest),
                ctypes.cast(ctypes.c_char_p(context), ctypes.POINTER(ctypes.c_uint8)),
                len(context),
                ctypes.cast(ctypes.c_char_p(hashoid), ctypes.POINTER(ctypes.c_uint8)),
                len(hashoid),
            )
        )
        if ret not in {Err.OK, Err.VERIFICATION_FAILURE}:
            raise Exception(
                f"ml_dsa_{self._strength}_hash_verify() " f"returned {ret} ({ret.name})"
            )
        return ret == Err.OK


class PrivateKey:
    """ML-DSA Private Key

    Serialize this object by asking for it as `bytes`.

    sign() a message with a given context to get back a bytes object that is a signature.
    """

    def __init__(self, data: Union[bytes, int]) -> None:
        """Create ML-DSA Private Key from bytes (or strength level)."""
        if isinstance(data, bytes):
            self._strength = _ML_DSA.strength_from_length("PRIVKEY_SIZE", len(data))
        elif isinstance(data, int):
            self._strength = data
        else:
            raise Exception(
                "Initialize ML-DSA Private Key with bytes "
                f"or a strength level, not {type(data)}"
            )
        self._ffi = _ML_DSA.strength(self._strength)
        self._privkey = self._ffi["PrivateKey"]()
        if isinstance(data, bytes):
            self._set(data)

    def __repr__(self) -> str:
        return f"<ML-DSA-{self._strength} Private Key>"

    def __bytes__(self) -> bytes:
        return bytes(self._privkey.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._privkey.data):
            raise ValueError(
                f"Expected {len(self._privkey.data)} bytes, " f"got {len(data)}"
            )
        for i in range(len(data)):
            self._privkey.data[i] = data[i]

    def sign(
        self,
        message: bytes,
        context: bytes = b"",
        hedged: Union[bool, Seed, bytes] = True,
    ) -> bytes:
        """Sign the `message` in the given `context`, producing a bytes representation of a signature.

        For normal hedged signatures, leave `hedged` set to `True` (the default).
        For deterministic signatures, pass `hedged=False`.
        For hedged signatures with your own source of randomness, pass a Seed or bytes object of size SEED_SIZE
        """
        if not isinstance(message, bytes):
            raise TypeError(
                f"{self}.sign wants a message of type bytes, got {type(message)}"
            )
        if not isinstance(context, bytes):
            raise TypeError(
                f"{self}.sign wants a context of type bytes, got {type(context)}"
            )
        sig = self._ffi["Signature"]()
        seed: _Seed
        det = Seed(b"\x00" * 32)
        if hedged is False:
            seed = det._seed
        elif isinstance(hedged, Seed):
            seed = hedged._seed
        elif isinstance(hedged, bytes):
            if len(hedged) != ML_DSA.SEED_SIZE:
                raise Exception(
                    f"Expected a seed of length {ML_DSA.SEED_SIZE}, got {len(hedged)} bytes"
                )
            seed = _Seed()
            for i in range(ML_DSA.SEED_SIZE):
                seed.data[i] = hedged[i]
        ret = Err(
            self._ffi["sign"](
                ctypes.byref(self._privkey),
                ctypes.cast(ctypes.c_char_p(message), ctypes.POINTER(ctypes.c_uint8)),
                len(message),
                ctypes.cast(ctypes.c_char_p(context), ctypes.POINTER(ctypes.c_uint8)),
                len(context),
                None if hedged is True else ctypes.byref(seed),
                ctypes.byref(sig),
            )
        )
        if ret is not Err.OK:
            raise Exception(
                f"ml_dsa_{self._strength}_sign() " f"returned {ret} ({ret.name})"
            )
        return bytes(sig.data)

    def hash_sign(
        self,
        digest: bytes,
        hashoid: Union[bytes, HashOID],
        context: bytes = b"",
        hedged: Union[bool, Seed, bytes] = True,
    ) -> bytes:
        """Sign a message hash `digest` in the given `context`, producing a bytes representation of a signature.

        The `hashoid` parameter is a DER-encoded OID that identifies the hash algorithm used.
        As a convenience, fips204.HashOID contains a list of DER-encoded OIDs of common digest algorithms.

        For normal hedged signatures, leave `hedged` set to `True` (the default).
        For deterministic signatures, pass `hedged=False`.
        For hedged signatures with your own source of randomness, pass a Seed or bytes object of size SEED_SIZE
        """
        if not isinstance(digest, bytes):
            raise TypeError(
                f"{self}.hash_sign wants a digest of type bytes, got {type(digest)}"
            )
        if not isinstance(context, bytes):
            raise TypeError(
                f"{self}.hash_sign wants a context of type bytes, got {type(context)}"
            )
        if isinstance(hashoid, HashOID):
            hashoid = hashoid.value
        if not isinstance(hashoid, bytes):
            raise TypeError(
                f"{self}.hash_sign wants a hashoid of type bytes or HashOID, got {type(hashoid)}"
            )
        sig = self._ffi["Signature"]()
        seed: _Seed
        det = Seed(b"\x00" * 32)
        if hedged is False:
            seed = det._seed
        elif isinstance(hedged, Seed):
            seed = hedged._seed
        elif isinstance(hedged, bytes):
            if len(hedged) != ML_DSA.SEED_SIZE:
                raise Exception(
                    f"Expected a seed of length {ML_DSA.SEED_SIZE}, got {len(hedged)} bytes"
                )
            seed = _Seed()
            for i in range(ML_DSA.SEED_SIZE):
                seed.data[i] = hedged[i]
        ret = Err(
            self._ffi["hash_sign"](
                ctypes.byref(self._privkey),
                ctypes.cast(ctypes.c_char_p(digest), ctypes.POINTER(ctypes.c_uint8)),
                len(digest),
                ctypes.cast(ctypes.c_char_p(context), ctypes.POINTER(ctypes.c_uint8)),
                len(context),
                ctypes.cast(ctypes.c_char_p(hashoid), ctypes.POINTER(ctypes.c_uint8)),
                len(hashoid),
                None if hedged is True else ctypes.byref(seed),
                ctypes.byref(sig),
            )
        )
        if ret is not Err.OK:
            raise Exception(
                f"ml_dsa_{self._strength}_hash_sign() " f"returned {ret} ({ret.name})"
            )
        return bytes(sig.data)


class _ML_DSA:
    params: Dict[int, Dict[str, int]] = {
        44: {
            "PUBKEY_SIZE": 1312,
            "PRIVKEY_SIZE": 2560,
            "SIG_SIZE": 2420,
        },
        65: {
            "PUBKEY_SIZE": 1952,
            "PRIVKEY_SIZE": 4032,
            "SIG_SIZE": 3309,
        },
        87: {
            "PUBKEY_SIZE": 2592,
            "PRIVKEY_SIZE": 4896,
            "SIG_SIZE": 4627,
        },
    }
    testlibpath = environ.get("FIPS204_PYTHON_TESTING_LIBRARY", None)
    if testlibpath is not None:
        lib = ctypes.CDLL(testlibpath)
    else:
        lib = ctypes.CDLL(ctypes.util.find_library("fips204"))

    # use Any below because i don't know how to specify the type of the FuncPtr
    ffi: Dict[int, Dict[str, Any]] = {}

    @classmethod
    def strength(cls, level: int) -> Dict[str, Any]:
        if level not in cls.ffi:

            class _PublicKey(ctypes.Structure):
                _fields_ = [("data", ctypes.c_uint8 * cls.params[level]["PUBKEY_SIZE"])]

            class _PrivateKey(ctypes.Structure):
                _fields_ = [
                    ("data", ctypes.c_uint8 * cls.params[level]["PRIVKEY_SIZE"])
                ]

            class _Signature(ctypes.Structure):
                _fields_ = [("data", ctypes.c_uint8 * cls.params[level]["SIG_SIZE"])]

            ffi: Dict[str, Any] = {}

            ffi["keygen_from_seed"] = cls.lib[f"ml_dsa_{level}_keygen_from_seed"]
            ffi["keygen_from_seed"].argtypes = [
                ctypes.POINTER(_Seed),
                ctypes.POINTER(_PublicKey),
                ctypes.POINTER(_PrivateKey),
            ]
            ffi["keygen_from_seed"].restype = ctypes.c_uint8

            ffi["sign"] = cls.lib[f"ml_dsa_{level}_sign_with_seed"]
            ffi["sign"].argtypes = [
                ctypes.POINTER(_PrivateKey),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(_Seed),
                ctypes.POINTER(_Signature),
            ]
            ffi["sign"].restype = ctypes.c_uint8

            ffi["hash_sign"] = cls.lib[f"ml_dsa_{level}_hash_sign_with_seed"]
            ffi["hash_sign"].argtypes = [
                ctypes.POINTER(_PrivateKey),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(_Seed),
                ctypes.POINTER(_Signature),
            ]
            ffi["hash_sign"].restype = ctypes.c_uint8

            ffi["verify"] = cls.lib[f"ml_dsa_{level}_verify"]
            ffi["verify"].argtypes = [
                ctypes.POINTER(_PublicKey),
                ctypes.POINTER(_Signature),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
            ]
            ffi["verify"].restype = ctypes.c_uint8

            ffi["hash_verify"] = cls.lib[f"ml_dsa_{level}_hash_verify"]
            ffi["hash_verify"].argtypes = [
                ctypes.POINTER(_PublicKey),
                ctypes.POINTER(_Signature),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
            ]
            ffi["hash_verify"].restype = ctypes.c_uint8

            ffi["PublicKey"] = _PublicKey
            ffi["PrivateKey"] = _PrivateKey
            ffi["Signature"] = _Signature

            cls.ffi[level] = ffi

        return cls.ffi[level]

    @classmethod
    def strength_from_length(cls, object_type: str, object_len: int) -> int:
        for strength in cls.params:
            if cls.params[strength][object_type] == object_len:
                return strength
        raise Exception(
            f"No ML-DSA parameter set has {object_type} " f"of {object_len} bytes"
        )

    @classmethod
    def _keygen_from_seed(
        cls, strength: int, seed: Optional[Seed]
    ) -> Tuple[PublicKey, PrivateKey]:
        pubkey = PublicKey(strength)
        privkey = PrivateKey(strength)

        ret = Err(
            cls.strength(strength)["keygen_from_seed"](
                None if seed is None else ctypes.byref(seed._seed),
                ctypes.byref(pubkey._pubkey),
                ctypes.byref(privkey._privkey),
            )
        )
        if ret is not Err.OK:
            raise Exception(
                f"ml_dsa_{strength}_keygen_from_seed() returned " f"{ret} ({ret.name})"
            )
        return (pubkey, privkey)


class ML_DSA(ABC):
    """Abstract base class for all ML-DSA (FIPS 204) parameter sets."""

    _strength: int
    PUBKEY_SIZE: int
    PRIVKEY_SIZE: int
    SIG_SIZE: int
    SEED_SIZE: int = 32

    @classmethod
    def keygen(cls, seed: Optional[Seed] = None) -> Tuple[PublicKey, PrivateKey]:
        """Generate a pair of Encapsulation and Decapsulation Keys.

        If a Seed is supplied, do a deterministic generation from the seed.
        Otherwise, randomly generate the key."""
        return _ML_DSA._keygen_from_seed(cls._strength, seed)


class ML_DSA_44(ML_DSA):
    """ML-DSA-44 (FIPS 204) Implementation."""

    _strength: int = 44
    PUBKEY_SIZE: int = 1312
    PRIVKEY_SIZE: int = 2560
    SIG_SIZE: int = 2420


class ML_DSA_65(ML_DSA):
    """ML-DSA-65 (FIPS 204) Implementation."""

    _strength: int = 65
    PUBKEY_SIZE: int = 1952
    PRIVKEY_SIZE: int = 4032
    SIG_SIZE: int = 3309


class ML_DSA_87(ML_DSA):
    """ML-DSA-87 (FIPS 204) Implementation."""

    _strength: int = 87
    PUBKEY_SIZE: int = 2592
    PRIVKEY_SIZE: int = 4896
    SIG_SIZE: int = 4627

#!/usr/bin/python3
"""Tests for fips204 python module

From the ffi/python/ directory, do:

PYTHONPATH=. test/nist/keygen.py

"""

from __future__ import annotations

import fips204
import json
import re
from binascii import a2b_hex, b2a_hex
import logging
import os
import hashlib

from typing import Dict, Union, List, TypedDict


class TestData(TypedDict):
    tcId: int
    deferred: bool
    pk: str
    sk: str


class KeyGenTestData(TestData):
    seed: str


class SigTestData(TestData):
    message: str
    context: str
    hashAlg: str


class SigTestData(TestData):
    message: str
    context: str
    hashAlg: str


class Test:
    tcId: int

    def __init__(self, data: TestData) -> None:
        self.tcId = int(data["tcId"])
        self.deferred = data["deferred"]
        self.pk = a2b_hex(data["pk"])
        self.sk = a2b_hex(data["sk"])

    def run(self, g: TestGroup) -> None:
        raise NotImplementedError()


class TestGroupData(TypedDict):
    tgId: int
    testType: str
    parameterSet: str


class KeyGenTestGroupData(TestGroupData):
    tests: List[KeyGenTestData]


class SigGenTestGroupData(TestGroupData):
    tests: List[SigGenTestData]


class SigVerTestGroupData(TestGroupData):
    tests: List[SigVerTestData]


class TestGroupException(Exception):
    pass


class TestGroup:
    param_matcher = re.compile("^ML-DSA-(?P<strength>44|65|87)$")
    tgId: int
    testType: str

    def __init__(self, d: TestGroupData) -> None:
        self.tgId = d["tgId"]
        self.testType: str = d["testType"]
        assert self.testType == "AFT"  # i don't know what AFT means
        self.parameterSet: str = d["parameterSet"]
        m = self.param_matcher.match(self.parameterSet)
        assert m
        self.strength: int = int(m["strength"])

    def run(self) -> None:
        for t in self.tests:
            t.run(self)

    def __len__(self) -> int:
        return len(self.tests)


class KeyGenTest(Test):
    def __init__(self, data: KeyGenTestData) -> None:
        super().__init__(data)
        self.seed = a2b_hex(data["seed"])

    def run(self, group: TestGroup) -> None:
        seed = fips204.Seed(self.seed)
        pubkey, privkey = seed.keygen(group.strength)
        if bytes(pubkey) != self.pk:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) pubkey failed:
                   got: {b2a_hex(bytes(pubkey))!r}
                wanted: {b2a_hex(self.pk)!r}"""
            )
        if bytes(privkey) != self.sk:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) privkey failed:
                   got: {b2a_hex(bytes(privkey))!r}
                wanted: {b2a_hex(self.sk)!r}"""
            )
        logging.info(f"passed keyGen {self.tcId}")


class SigTest(Test):
    def __init__(self, data: SigTestData) -> None:
        super().__init__(data)
        self.signature = a2b_hex(data["signature"])
        self.message = a2b_hex(data["message"])
        self.context = a2b_hex(data["context"])
        self.hashAlg = data["hashAlg"]


def digest_message(alg: str, msg: bytes) -> bytes:
    if alg.startswith("SHAKE-"):
        dlen = int(alg[6:]) // 4
        return hashlib.new(alg, msg).digest(dlen)
    else:
        return hashlib.new(alg, msg).digest()


class SigGenTest(SigTest):
    def __init__(self, data: SigGenTestData) -> None:
        super().__init__(data)
        self.rnd = None
        if "rnd" in data and isinstance(data["rnd"], str):
            self.rnd = a2b_hex(data["rnd"])

    def run(self, group: TestGroup) -> None:
        priv = fips204.PrivateKey(self.sk)
        sig: bytes
        if self.hashAlg == "none":
            sig = priv.sign(
                self.message,
                context=self.context,
                hedged=False if self.rnd is None else self.rnd,
            )
        else:
            sig = priv.hash_sign(
                digest_message(self.hashAlg, self.message),
                fips204.HashOID[self.hashAlg],
                context=self.context,
                hedged=False if self.rnd is None else self.rnd,
            )
        if sig != self.signature:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) sigGen failed:
                   got: {b2a_hex(sig)!r}
                wanted: {b2a_hex(self.signature)!r}"""
            )
        logging.info(f"passed sigGen {self.tcId}")


class SigVerTest(SigTest):
    def __init__(self, data: SigVerTestData) -> None:
        super().__init__(data)
        self.testpassed = data["testPassed"]

    def run(self, group: TestGroup) -> None:
        pub = fips204.PublicKey(self.pk)
        if self.hashAlg == "none":
            verif = pub.verify(self.signature, self.message, context=self.context)
        else:
            verif = pub.hash_verify(
                self.signature,
                digest_message(self.hashAlg, self.message),
                fips204.HashOID[self.hashAlg],
                context=self.context,
            )
        if verif != self.testpassed:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) sigVer failed
                   got: {verif}
                wanted: {self.testpassed}"""
            )
        logging.info(f"passed sigVer {self.tcId}")


class KeyGenTestGroup(TestGroup):
    def __init__(self, d: KeyGenTestGroupData) -> None:
        super().__init__(d)
        self.tests: List[KeyGenTest] = []
        for t in d["tests"]:
            self.tests.append(KeyGenTest(t))


class SigGenTestGroup(TestGroup):
    def __init__(self, d: SigGenTestGroupData) -> None:
        super().__init__(d)
        self.tests: List[SigGenTest] = []
        self.external = d["signatureInterface"] == "external"
        if self.external:
            for t in d["tests"]:
                self.tests.append(SigGenTest(t))

    def run(self) -> None:
        if self.external:
            super().run()
        else:
            raise TestGroupException(
                f"skipping sigGen test group {self.tgId}, not an external interface"
            )


class SigVerTestGroup(TestGroup):
    def __init__(self, d: SigVerTestGroupData) -> None:
        super().__init__(d)
        self.tests: List[SigGenTest] = []
        self.external = d["signatureInterface"] == "external"
        self.prehash = d["preHash"] == "preHash"
        if self.external:
            for t in d["tests"]:
                self.tests.append(SigVerTest(t))

    def run(self) -> None:
        if self.external:
            super().run()
        else:
            raise TestGroupException(
                f"skipping sigVer test group {self.tgId}, not an external interface"
            )


def process(testtype: str) -> None:
    with open(
        f"../../tests/nist_vectors/ML-DSA-{testtype}-FIPS204/internalProjection.json"
    ) as f:
        t = json.load(f)
        assert t["vsId"] == 42
        assert t["algorithm"] == "ML-DSA"
        assert t["revision"] == "FIPS204"
        assert t["isSample"] == False
        assert t["mode"] == testtype
        groups: List[TestGroup] = []
        if testtype == "keyGen":
            for g in t["testGroups"]:
                groups.append(KeyGenTestGroup(g))
        elif testtype == "sigGen":
            for g in t["testGroups"]:
                groups.append(SigGenTestGroup(g))
        elif testtype in ["sigVer"]:
            for g in t["testGroups"]:
                groups.append(SigVerTestGroup(g))
        else:
            raise Exception(f"Unknown Test Type {testtype}")
        tests = 0
        for group in groups:
            try:
                group.run()
                tests += len(group)
            except TestGroupException as e:
                logging.info(e)
        print(f"Passed {tests} tests in {len(groups)} {testtype} groups")


if os.environ.get("VERBOSE", None) is not None:
    logging.basicConfig(level=logging.DEBUG)

for t in ["keyGen", "sigGen", "sigVer"]:
    process(t)

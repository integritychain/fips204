#!/usr/bin/python3

"""Generate C source to test libfips204"""

import json

from typing import Tuple


def convert_bytes(h: str, nybblesperline: int = 16, indent: int = 4) -> str:
    """convert a hex string into a C representation of an array"""
    out = ""
    linelen = nybblesperline * 2
    while len(h):
        line = h[:linelen]
        h = h[len(line) :]
        out += " " * indent + ", ".join(
            f"0x{line[x:x+2]}" for x in range(0, len(line), 2)
        )
        if len(h):
            out += ","
        out += "\n"
    return out


def struct(h: str, typ: str, ps: int, x: int) -> str:
    if typ == "seed":
        cls = "ml_dsa_seed"
    else:
        cls = f"ml_dsa_{ps}_{typ}"
    return f"const {cls} {typ}_{x} = " + "{ .data = {\n" + convert_bytes(h) + "  } };\n"


def buf(h: str, name: str, x: int) -> Tuple[str, str]:
    """returns a buffer and sizeof the buffer, with a special case for empty buffer"""
    if len(h):
        return (
            f"const uint8_t {name}_{x}[] = " + "{\n" + convert_bytes(h) + "  };\n",
            f"sizeof({name}_{x})",
        )
    else:
        return (f"const uint8_t *{name}_{x} = NULL;\n", "0")


def keygen(f: str) -> str:
    d = json.load(open(f))
    out = """
int keygen() {
  int testcount = 0;
  int errcount = 0;
    """
    if d["mode"] != "keyGen":
        raise Exception(f"expected keyGen data, got {d["mode"]}")
    for tg in d["testGroups"]:
        ps = int(tg["parameterSet"][-2:])

        for t in tg["tests"]:
            tid = int(t["tcId"])
            pk = struct(t["pk"], "public_key", ps, tid)
            sk = struct(t["sk"], "private_key", ps, tid)
            seed = struct(t["seed"], "seed", ps, tid)

            out += f"""
  {pk}
  {sk}
  {seed}
  testcount ++;
  if (ml_dsa_{ps}_keygen_test ({tid}, &seed_{tid}, &public_key_{tid}, &private_key_{tid}))
     errcount++;
"""
    return out + """
  if (errcount) {
    fprintf(stderr, "%d/%d keygen tests failed\\n", errcount, testcount);
  } else {
    fprintf(stderr, "%d keygen tests passed\\n", testcount);
  }
  return errcount;
}
"""


def sigver(f: str) -> str:
    d = json.load(open(f))
    skipped = 0
    out = """
int sigver() {
  int testcount = 0;
  int errcount = 0;
    """
    if d["mode"] != "sigVer":
        raise Exception(f"expected sigVer data, got {d["mode"]}")
    for tg in d["testGroups"]:
        ps = int(tg["parameterSet"][-2:])
        for t in tg["tests"]:
            if tg["signatureInterface"] != "external":
                skipped += 1
            else:
                if tg["preHash"] == "preHash":
                    skipped += 1
                else:
                    tid = int(t["tcId"])
                    msg, msglen = buf(t["message"], "message", tid)
                    ctx, ctxlen = buf(t["context"], "ctx", tid)
                    out += f"""
  {struct(t["pk"], "public_key", ps, tid)}
  {struct(t["signature"], "signature", ps, tid)}
  {msg}
  {ctx}
  testcount ++;
  if (ml_dsa_{ps}_sigver_test ({tid}, &public_key_{tid}, &signature_{tid},
      message_{tid}, {msglen},
      ctx_{tid}, {ctxlen},
      {str(t["testPassed"]).lower()}))
     errcount++;
"""

    return out + f"""
  if (errcount) {{
    fprintf(stderr, "%d/%d sigver tests failed ({skipped} skipped)\\n", errcount, testcount);
  }} else {{
    fprintf(stderr, "%d sigver tests passed ({skipped} skipped)\\n", testcount);
  }}
  return errcount;
}}
"""


def siggen(f: str) -> str:
    d = json.load(open(f))
    skipped = 0
    out = """
int siggen() {
  int testcount = 0;
  int errcount = 0;
    """
    if d["mode"] != "sigGen":
        raise Exception(f"expected sigGen data, got {d["mode"]}")
    for tg in d["testGroups"]:
        ps = int(tg["parameterSet"][-2:])
        for t in tg["tests"]:
            if tg["signatureInterface"] != "external" or not tg["deterministic"]:
                skipped += 1
            else:
                if tg["preHash"] == "preHash":
                    skipped += 1
                else:
                    tid = int(t["tcId"])
                    msg, msglen = buf(t["message"], "message", tid)
                    ctx, ctxlen = buf(t["context"], "ctx", tid)
                    out += f"""
  {struct(t["sk"], "private_key", ps, tid)}
  {struct(t["signature"], "signature", ps, tid)}
  {msg}
  {ctx}
  testcount ++;
  if (ml_dsa_{ps}_siggen_test ({tid}, &private_key_{tid}, &signature_{tid},
      message_{tid}, {msglen},
      ctx_{tid}, {ctxlen}))
     errcount++;
"""

    return out + f"""
  if (errcount) {{
    fprintf(stderr, "%d/%d siggen tests failed ({skipped} skipped)\\n", errcount, testcount);
  }} else {{
    fprintf(stderr, "%d siggen tests passed ({skipped} skipped)\\n", testcount);
  }}
  return errcount;
}}
"""


def prefix() -> str:
    out = """/* testing libfips204 against NIST test vectors */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fips204.h>
"""

    for pc in ["44", "65", "87"]:
        prefix = ""
        suffix = ""
        for term in [
            "keygen_test",
            "sigver_test",
            "siggen_test",
            "keygen_from_seed",
            "public_key",
            "private_key",
            "signature",
            "verify",
            "sign_deterministic",
        ]:
            prefix += f"#define MLDSA_{term} ml_dsa_{pc}_{term}\n"
            suffix += f"#undef MLDSA_{term}\n"

        out += prefix + '#include "nist-tests-template.c"\n' + suffix
    out += """

int keygen();
int sigver();
int siggen();

int
main (int argc, const char **argv) {
  int errcount = 0;
  errcount += keygen();
  errcount += sigver();
  errcount += siggen();
  if (errcount) {
    fprintf(stderr, "%d failures\\n", errcount);
    return 1;
  } else {
    fprintf(stderr, "All tests passed!\\n");
    return 0;
  }
}
"""
    return out


print(prefix())
print(keygen("../../tests/nist_vectors/ML-DSA-keyGen-FIPS204/internalProjection.json"))
print(sigver("../../tests/nist_vectors/ML-DSA-sigVer-FIPS204/internalProjection.json"))
print(siggen("../../tests/nist_vectors/ML-DSA-sigGen-FIPS204/internalProjection.json"))

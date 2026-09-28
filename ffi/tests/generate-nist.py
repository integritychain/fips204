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
results keygen() {
  results ret = { 0,0,0 };
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
  ret.tests++;
  if (ml_dsa_{ps}_keygen_test ({tid}, &seed_{tid}, &public_key_{tid}, &private_key_{tid}))
     ret.failed++;
"""
    return out + """
  if (ret.failed) {
    fprintf(stderr, "%d/%d keygen tests failed\\n", ret.failed, ret.tests);
  } else {
    fprintf(stderr, "%d keygen tests passed\\n", ret.tests);
  }
  return ret;
}
"""

class hasher:
    def __init__(self, tid: int, algo: str) -> None:
        if algo in ['SHA2-512/224']:
            raise Exception(f"{algo} not supported")
        self.tid = tid
        self.algo = algo
        algo = algo.replace('/', '_')
        self.ctx = algo.replace('-', '_') + "_CTX"
        self.prefix = algo.replace("SHA2-", "SHA").replace("-", "_")
        self.hashoid = "ML_DSA_" + algo.replace("-", "_")
        self.hashlen = self.prefix + "_DIGEST_LENGTH"
        if algo.startswith("SHA2"):
            self.ctx = "SHA2_CTX"
        elif algo.startswith("SHAKE"):
            self.ctx = algo.replace("-", "") + "_CTX"
            self.hashlen = int(algo.split('-')[1])//4
            self.prefix = algo.replace("-","") + "_"
        elif algo.startswith("SHA3"):
            self.prefix += "_"
    def prep(self) -> str:
        out = f"""
  uint8_t hash_{self.tid}[{self.hashlen}];
  {self.ctx} hashctx_{self.tid};
  {self.prefix}Init(&hashctx_{self.tid});
  {self.prefix}Update(&hashctx_{self.tid}, message_{self.tid}, sizeof(message_{self.tid}));
"""
        if self.algo.startswith("SHAKE"):
            out += f"  {self.prefix}Final(hash_{self.tid}, {self.hashlen}, &hashctx_{self.tid});\n"
        else:
            out += f"  {self.prefix}Final(hash_{self.tid}, &hashctx_{self.tid});\n"
        return out
    @property
    def oid(self) -> str:
        return self.hashoid


def sigver(f: str) -> str:
    d = json.load(open(f))
    out = """
results sigver() {
   results ret = { 0,0,0 };
    """
    if d["mode"] != "sigVer":
        raise Exception(f"expected sigVer data, got {d["mode"]}")
    for tg in d["testGroups"]:
        ps = int(tg["parameterSet"][-2:])
        for t in tg["tests"]:
            tid = int(t["tcId"])
            if tg["signatureInterface"] != "external":
                out += f"""
  /* Skipping {tg["signatureInterface"]} interface test {tid} */
  ret.skipped++;
"""
            else:
                msg, msglen = buf(t["message"], "message", tid)
                ctx, ctxlen = buf(t["context"], "ctx", tid)
                start = f"""
  {struct(t["pk"], "public_key", ps, tid)}
  {struct(t["signature"], "signature", ps, tid)}
  {msg}
  {ctx}
  ret.tests ++;
"""
                if tg["preHash"] == "preHash":
                    try:
                        h = hasher(tid, t["hashAlg"])
                        out += start + f"""
  {h.prep()}
  if (ml_dsa_{ps}_hash_sigver_test ({tid}, &public_key_{tid}, &signature_{tid},
      hash_{tid}, sizeof(hash_{tid}),
      ctx_{tid}, {ctxlen},
      {h.oid}, sizeof({h.oid}),
      {str(t["testPassed"]).lower()}))
     ret.failed++;
"""
                    except Exception as e:
                        out += f"""
  /* Skipping test {tid}: {e} */
  ret.skipped ++;
"""
                else:
                    out += start + f"""
  if (ml_dsa_{ps}_sigver_test ({tid}, &public_key_{tid}, &signature_{tid},
      message_{tid}, {msglen},
      ctx_{tid}, {ctxlen},
      {str(t["testPassed"]).lower()}))
     ret.failed++;
"""

    return out + f"""
  if (ret.failed) {{
    fprintf(stderr, "%d/%d sigver tests failed (%d skipped)\\n", ret.failed, ret.tests, ret.skipped);
  }} else {{
    fprintf(stderr, "%d sigver tests passed (%d skipped)\\n", ret.tests, ret.skipped);
  }}
  return ret;
}}
"""


def siggen(f: str) -> str:
    d = json.load(open(f))
    out = """
results siggen() {
  results ret = { 0,0,0 };
    """
    if d["mode"] != "sigGen":
        raise Exception(f"expected sigGen data, got {d["mode"]}")
    for tg in d["testGroups"]:
        ps = int(tg["parameterSet"][-2:])
        for t in tg["tests"]:
            tid = int(t["tcId"])
            if tg["signatureInterface"] != "external" or not tg["deterministic"]:
                out += f"""
  /* Skipping {tg["signatureInterface"]} interface test {tid} */
  ret.skipped++;
"""
            else:
                msg, msglen = buf(t["message"], "message", tid)
                ctx, ctxlen = buf(t["context"], "ctx", tid)
                start = f"""
  {struct(t["sk"], "private_key", ps, tid)}
  {struct(t["signature"], "signature", ps, tid)}
  {msg}
  {ctx}
  ret.tests ++;
"""
                if tg["preHash"] == "preHash":
                    try:
                        h = hasher(tid, t["hashAlg"])
                        out += start + f"""
  {h.prep()}
  if (ml_dsa_{ps}_hash_siggen_test ({tid}, &private_key_{tid}, &signature_{tid},
      hash_{tid}, sizeof(hash_{tid}),
      ctx_{tid}, {ctxlen},
      {h.oid}, sizeof({h.oid})))
     ret.failed++;
"""
                    except Exception as e:
                        out += f"""
  /* Skipping test {tid}: {e} */
  ret.skipped ++;
"""
                else:
                    out += start + f"""
  if (ml_dsa_{ps}_siggen_test ({tid}, &private_key_{tid}, &signature_{tid},
      message_{tid}, {msglen},
      ctx_{tid}, {ctxlen}))
     ret.failed++;
"""

    return out + f"""
  if (ret.failed) {{
    fprintf(stderr, "%d/%d siggen tests failed (%d skipped)\\n", ret.failed, ret.tests, ret.skipped);
  }} else {{
    fprintf(stderr, "%d siggen tests passed (%d skipped)\\n", ret.tests, ret.skipped);
  }}
  return ret;
}}
"""


def prefix() -> str:
    out = """/* testing libfips204 against NIST test vectors */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fips204.h>

#ifdef HAVE_LIBMD
#include <sha2.h>
#include <sha3.h>
#endif

typedef struct {
  int tests;
  int skipped;
  int failed;
} results;
"""

    for pc in ["44", "65", "87"]:
        prefix = ""
        suffix = ""
        for term in [
            "keygen_test",
            "sigver_test",
            "hash_sigver_test",
            "hash_siggen_test",
            "siggen_test",
            "keygen_from_seed",
            "public_key",
            "private_key",
            "signature",
            "verify",
            "hash_verify",
            "sign_deterministic",
            "hash_sign_deterministic",
        ]:
            prefix += f"#define MLDSA_{term} ml_dsa_{pc}_{term}\n"
            suffix += f"#undef MLDSA_{term}\n"

        out += prefix + '#include "nist-tests-template.c"\n' + suffix
    out += """

results keygen();
results sigver();
results siggen();

int
main (int argc, const char **argv) {
  results res[3] = { {0,0,0},{0,0,0},{0,0,0} };
  results total = { 0, 0, 0 };
  res[0] = keygen();
  res[1] = sigver();
  res[2] = siggen();
  for (int i = 0; i < 3; i++) {
    total.tests += res[i].tests;
    total.skipped += res[i].skipped;
    total.failed += res[i].failed;
  }
  if (total.failed) {
    fprintf(stderr, "%d failures\\n", total.failed);
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

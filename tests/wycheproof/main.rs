// This file runs the Wycheproof ML-DSA vectors (Apache-2.0), stored gzipped (gzip -9 -n).
//   from: https://github.com/C2SP/wycheproof/tree/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1
//   files: mldsa_{44,65,87}_{sign_seed_test,sign_noseed_test,verify_test}.json
//
// Every case in each file runs through the public API, apart from the cases that give µ in
// place of a message (flag `Internal`), which call the `acvp-internal` hooks. A key, seed or
// signature of the wrong length cannot be expressed with the crate's fixed-size types, so such a
// case is counted as length-only and must be marked invalid. A valid signature must also verify,
// and a key expanded from a seed must match the group's public key. Each test counts its cases
// and fails unless every one was handled, apart from parameter sets whose feature is off. An
// unknown schema, group type, field, result or flag fails the test. This harness and its
// vectors are excluded from the published crate.

// The `acvp-internal` hooks are deprecated so that nothing outside the tests calls them.
#![allow(deprecated)]

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use flate2::read::GzDecoder;
use hex::decode;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use std::fs::File;
use std::io::Read;

#[cfg(feature = "ml-dsa-44")]
use fips204::ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
use fips204::ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
use fips204::ml_dsa_87;


const SETS: [&str; 3] = ["44", "65", "87"];

const SIGN_FIELDS: [&str; 9] =
    ["comment", "ctx", "flags", "msg", "mu", "result", "rnd", "sig", "tcId"];

const VERIFY_FIELDS: [&str; 7] = ["comment", "ctx", "flags", "msg", "result", "sig", "tcId"];

const KNOWN_FLAGS: [&str; 16] = [
    "BoundaryCondition",
    "IncorrectPrivateKeyLength",
    "IncorrectPublicKeyLength",
    "IncorrectSignatureLength",
    "InfinityNormViolation",
    "Internal",
    "InvalidContext",
    "InvalidHintsEncoding",
    "InvalidPrivateKey",
    "InvalidSignature",
    "ManySteps",
    "MissingReduction",
    "ModifiedSignature",
    "Randomized",
    "ValidSignature",
    "ZeroPublicKey",
];


// ----- RNG THAT SUPPLIES A CASE'S `rnd` -----
struct FixedRng([u8; 32]);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) { out.copy_from_slice(&self.0) }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}


// ----- ACCOUNTING: EVERY CASE IN A FILE IS HANDLED, OR THE TEST FAILS -----
struct Tally {
    total: usize,
    ran: usize,
    length_only: usize,
    feature_skipped: usize,
    hook_skipped: usize,
}

impl Tally {
    fn new() -> Self {
        Tally {
            total: 0,
            ran: 0,
            length_only: 0,
            feature_skipped: 0,
            hook_skipped: 0,
        }
    }

    fn count(&mut self, handled: bool, length_only: bool, hook_skipped: bool) {
        match (handled, length_only, hook_skipped) {
            (false, _, _) => self.feature_skipped += 1,
            (true, true, _) => self.length_only += 1,
            (true, false, true) => self.hook_skipped += 1,
            (true, false, false) => self.ran += 1,
        }
    }

    fn finish(&self, which: &str) {
        println!(
            "Wycheproof {which}: ran {}, length-only {}, feature-skipped {}, of {}",
            self.ran, self.length_only, self.feature_skipped, self.total
        );
        if self.hook_skipped > 0 {
            println!(
                "Wycheproof {which}: skipped {} µ cases; rerun with --features acvp-internal",
                self.hook_skipped
            );
        }
        let handled = self.ran + self.length_only + self.feature_skipped + self.hook_skipped;
        assert_eq!(handled, self.total, "Wycheproof {which}: some cases were not handled");
        assert!(self.ran > 0, "Wycheproof {which}: no cases ran");
    }
}

// Runs `$run!(module)` for the parameter set named `$set` and returns true. Returns false when
// that set's feature is off, and panics on a parameter set it does not know.
macro_rules! dispatch {
    ($set:expr, $run:ident) => {
        match $set {
            #[cfg(feature = "ml-dsa-44")]
            "44" => {
                $run!(ml_dsa_44);
                true
            }
            #[cfg(feature = "ml-dsa-65")]
            "65" => {
                $run!(ml_dsa_65);
                true
            }
            #[cfg(feature = "ml-dsa-87")]
            "87" => {
                $run!(ml_dsa_87);
                true
            }
            #[allow(unreachable_patterns)]
            "44" | "65" | "87" => false,
            other => panic!("unknown parameter set {other}"),
        }
    };
}

fn load(name: &str) -> Value {
    let path = format!("./tests/wycheproof/{name}.gz");
    let mut vectors = String::new();
    GzDecoder::new(File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}")))
        .read_to_string(&mut vectors)
        .unwrap_or_else(|e| panic!("gunzip {path}: {e}"));
    serde_json::from_str(&vectors).unwrap()
}

fn cases(group: &Value) -> &Vec<Value> { group["tests"].as_array().expect("tests") }

fn hex(v: &Value, key: &str, loc: &str) -> Vec<u8> {
    decode(v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))).unwrap()
}

/// An absent or null field gives `None`. An absent `ctx` is the empty context, an absent `rnd`
/// means deterministic signing, and a group whose key must be rejected has a null `publicKey`.
fn opt_hex(v: &Value, key: &str) -> Option<Vec<u8>> {
    v.get(key).filter(|x| !x.is_null()).map(|x| decode(x.as_str().expect("hex string")).unwrap())
}

fn valid(test: &Value) -> bool { test["result"] == "valid" }

/// The group type, and the group and case fields, of each kind of file.
fn layout(kind: &str) -> (&'static str, &'static [&'static str], &'static [&'static str]) {
    match kind {
        "sign_seed" => (
            "MlDsaSign",
            &["privateKeyPkcs8", "privateSeed", "publicKey", "source", "tests", "type"],
            &SIGN_FIELDS,
        ),
        "sign_noseed" => (
            "MlDsaSign",
            &["privateKey", "publicKey", "source", "tests", "type"],
            &SIGN_FIELDS,
        ),
        "verify" => (
            "MlDsaVerify",
            &["publicKey", "publicKeyDer", "source", "tests", "type"],
            &VERIFY_FIELDS,
        ),
        other => panic!("unknown file kind {other}"),
    }
}

/// Checks the file header and every group and case, adds the file's cases to the tally, and
/// returns the groups.
fn checked_groups<'a>(
    doc: &'a Value, file: &str, kind: &str, set: &str, tally: &mut Tally,
) -> &'a Vec<Value> {
    let (group_type, group_fields, case_fields) = layout(kind);
    assert_eq!(doc["algorithm"], format!("ML-DSA-{set}"), "{file}: algorithm");
    assert_eq!(doc["schema"], format!("mldsa_{kind}_schema.json"), "{file}: schema");
    let groups = doc["testGroups"].as_array().expect("testGroups");
    let count: usize = groups.iter().map(|g| cases(g).len()).sum();
    assert_eq!(Some(count as u64), doc["numberOfTests"].as_u64(), "{file}: numberOfTests");
    tally.total += count;
    for group in groups {
        for key in group.as_object().expect("group").keys() {
            assert!(group_fields.contains(&key.as_str()), "{file}: unknown group field {key}");
        }
        assert_eq!(group["type"], group_type, "{file}: group type");
        for test in cases(group) {
            let loc = format!("{file} tcId={}", test["tcId"]);
            for key in test.as_object().expect("test").keys() {
                assert!(case_fields.contains(&key.as_str()), "{loc}: unknown field {key}");
            }
            assert!(test["result"] == "valid" || test["result"] == "invalid", "{loc}: result");
            for flag in test["flags"].as_array().into_iter().flatten() {
                let flag = flag.as_str().expect("flag");
                assert!(KNOWN_FLAGS.contains(&flag), "{loc}: unknown flag {flag}");
            }
        }
    }
    groups
}


// Signing from a seed (sign_seed) or from an expanded private key (sign_noseed)
fn sign(kind: &str) {
    let mut tally = Tally::new();
    for set in SETS {
        let file = format!("mldsa_{set}_{kind}_test.json");
        let doc = load(&file);
        for group in checked_groups(&doc, &file, kind, set, &mut tally) {
            for test in cases(group) {
                let loc = format!("{file} tcId={}", test["tcId"]);
                let mut length_only = false;
                // A case that gives µ in place of a message needs the hooks
                let hook_skipped = test.get("msg").is_none() && !cfg!(feature = "acvp-internal");

                macro_rules! runtest {
                    ($pc:ident) => {{
                        // Null for a group whose key must be rejected
                        let pk_exp = opt_hex(group, "publicKey");
                        // None when the seed or key has the wrong length
                        let sk = if kind == "sign_seed" {
                            hex(group, "privateSeed", &loc).try_into().ok().map(|xi: [u8; 32]| {
                                let (pk, sk) = $pc::KG::keygen_from_seed(&xi);
                                if let Some(pk_exp) = &pk_exp {
                                    assert_eq!(
                                        *pk_exp,
                                        pk.into_bytes(),
                                        "{loc} seed expands to publicKey"
                                    );
                                }
                                Ok(sk)
                            })
                        } else {
                            hex(group, "privateKey", &loc)
                                .try_into()
                                .ok()
                                .map(|b: [u8; $pc::SK_LEN]| $pc::PrivateKey::try_from_bytes(b))
                        };
                        let rnd = opt_hex(test, "rnd");
                        let hedged = rnd.is_some();
                        let rnd: [u8; 32] = rnd.map_or([0u8; 32], |r| r.try_into().unwrap());
                        let ctx = opt_hex(test, "ctx").unwrap_or_default();
                        match sk {
                            None => {
                                length_only = true;
                                assert!(!valid(test), "{loc}: a wrong-length key is marked valid");
                            }
                            Some(Err(_)) => {
                                assert!(!valid(test), "{loc}: key rejected ({})", test["comment"])
                            }
                            Some(Ok(sk)) => {
                                let pk = sk.get_public_key();
                                if let Some(pk_exp) = &pk_exp {
                                    assert_eq!(*pk_exp, pk.clone().into_bytes(), "{loc} publicKey");
                                }
                                // (signature, whether it verifies); None when the hooks are off
                                let got = if test.get("msg").is_some() {
                                    let msg = hex(test, "msg", &loc);
                                    Some(
                                        sk.try_sign_with_seed(&rnd, &msg, &ctx)
                                            .map(|sig| (sig, pk.verify(&msg, &sig, &ctx))),
                                    )
                                } else {
                                    let mu: [u8; 64] = hex(test, "mu", &loc).try_into().unwrap();
                                    #[cfg(feature = "acvp-internal")]
                                    let got = Some(
                                        sk.sign_mu(&mut FixedRng(rnd), &mu, hedged)
                                            .map(|sig| (sig, pk.verify_mu(&mu, &sig))),
                                    );
                                    #[cfg(not(feature = "acvp-internal"))]
                                    let got = {
                                        let _ = (mu, hedged);
                                        None
                                    };
                                    got
                                };
                                match (got, valid(test)) {
                                    (None, _) => {}
                                    (Some(Ok((sig, verified))), true) => {
                                        assert_eq!(hex(test, "sig", &loc), sig, "{loc}");
                                        assert!(verified, "{loc} verify");
                                    }
                                    (Some(Err(_)), false) => {}
                                    (Some(Ok(_)), false) => {
                                        panic!(
                                            "{loc}: signed an invalid case ({})",
                                            test["comment"]
                                        )
                                    }
                                    (Some(Err(e)), true) => panic!("{loc}: {e}"),
                                }
                            }
                        }
                    }};
                }
                let handled = dispatch!(set, runtest);
                tally.count(handled, length_only, hook_skipped);
            }
        }
    }
    tally.finish(kind);
}

#[test]
fn wycheproof_sign_seed() { sign("sign_seed"); }

#[test]
fn wycheproof_sign_noseed() { sign("sign_noseed"); }

#[test]
fn wycheproof_verify() {
    let mut tally = Tally::new();
    for set in SETS {
        let file = format!("mldsa_{set}_verify_test.json");
        let doc = load(&file);
        for group in checked_groups(&doc, &file, "verify", set, &mut tally) {
            for test in cases(group) {
                let loc = format!("{file} tcId={}", test["tcId"]);
                let mut length_only = false;

                macro_rules! runtest {
                    ($pc:ident) => {{
                        let pk: Option<[u8; $pc::PK_LEN]> =
                            hex(group, "publicKey", &loc).try_into().ok();
                        let sig: Option<[u8; $pc::SIG_LEN]> =
                            hex(test, "sig", &loc).try_into().ok();
                        let ctx = opt_hex(test, "ctx").unwrap_or_default();
                        match (pk, sig) {
                            (Some(pk), Some(sig)) => {
                                let verified = $pc::PublicKey::try_from_bytes(pk)
                                    .is_ok_and(|pk| pk.verify(&hex(test, "msg", &loc), &sig, &ctx));
                                assert_eq!(valid(test), verified, "{loc} ({})", test["comment"]);
                            }
                            _ => {
                                length_only = true;
                                assert!(
                                    !valid(test),
                                    "{loc}: a wrong-length input is marked valid"
                                );
                            }
                        }
                    }};
                }
                let handled = dispatch!(set, runtest);
                tally.count(handled, length_only, false);
            }
        }
    }
    tally.finish("verify");
}

// This file applies the NIST ACVP vectors.
//   from: https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
//   from: https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json
//   from: https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
//
// Every vector in each file is applied. Each test counts the cases in its file and fails unless
// every one ran, apart from parameter sets whose feature is off. A group field or group kind
// that this harness does not know fails the test, so a new kind of NIST group is never skipped.
// The internal and external-µ groups call the `acvp-internal` hooks, which `cargo test`
// enables through the dev-dependency on this crate in Cargo.toml. `cargo package` drops that
// dev-dependency, so a test run from the published crate counts those groups as skipped unless
// it passes `--features acvp-internal`.

// The `acvp-internal` hooks are deprecated so that nothing outside the tests calls them.
#![allow(deprecated)]

use hex::decode;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use std::fs;

#[cfg(feature = "ml-dsa-44")]
use fips204::ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
use fips204::ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
use fips204::ml_dsa_87;

use fips204::traits::{SerDes,KeyGen,Verifier,Signer};

use fips204::pre_hash;

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

// ----- CUSTOM RNG TO REPLAY VALUES -----
struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("test rng problem");
        out.copy_from_slice(&x)
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

impl TestRng {
    fn new() -> Self { TestRng { data: Vec::new() } }

    fn push(&mut self, new_data: &[u8]) {
        let x = new_data.to_vec();
        self.data.push(x);
    }
}

// ----- ACCOUNTING: EVERY CASE IN A FILE RUNS, OR THE TEST FAILS -----
struct Tally {
    total: usize,
    ran: usize,
    feature_skipped: usize,
    hook_skipped: usize,
}

impl Tally {
    fn new(doc: &Value) -> Self {
        let total = groups(doc).iter().map(|g| cases(g).len()).sum();
        Tally { total, ran: 0, feature_skipped: 0, hook_skipped: 0 }
    }

    fn count(&mut self, handled: bool) {
        if handled { self.ran += 1 } else { self.feature_skipped += 1 }
    }

    fn finish(&self, which: &str) {
        println!("NIST {which}: ran {}, feature-skipped {}, of {}", self.ran, self.feature_skipped, self.total);
        if self.hook_skipped > 0 {
            println!("NIST {which}: skipped {} internal cases; rerun with --features acvp-internal", self.hook_skipped);
        }
        assert_eq!(
            self.ran + self.feature_skipped + self.hook_skipped,
            self.total,
            "NIST {which}: some cases did not run"
        );
        assert!(self.ran > 0, "NIST {which}: no cases ran");
    }
}

// Runs `$run!(module)` for the parameter set named `$set` and returns true. Returns false when
// that set's feature is off, and panics on a parameter set it does not know.
macro_rules! dispatch {
    ($set:expr, $run:ident) => {
        match $set {
            #[cfg(feature = "ml-dsa-44")]
            "ML-DSA-44" => { $run!(ml_dsa_44); true }
            #[cfg(feature = "ml-dsa-65")]
            "ML-DSA-65" => { $run!(ml_dsa_65); true }
            #[cfg(feature = "ml-dsa-87")]
            "ML-DSA-87" => { $run!(ml_dsa_87); true }
            #[allow(unreachable_patterns)]
            "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => false,
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// The signing interface that a sigGen or sigVer group applies.
#[derive(Clone, Copy)]
enum Kind {
    Pure,
    PreHash,
    Internal,
    ExternalMu,
}

fn kind_of(group: &Value) -> Kind {
    let iface = group["signatureInterface"].as_str();
    let pre = group["preHash"].as_str();
    let external_mu = group["externalMu"].as_bool();
    match (iface, pre, external_mu) {
        (Some("external"), Some("pure"), Some(false)) => Kind::Pure,
        (Some("external"), Some("preHash"), Some(false)) => Kind::PreHash,
        (Some("internal"), Some("none"), Some(false)) => Kind::Internal,
        (Some("internal"), Some("none"), Some(true)) => Kind::ExternalMu,
        other => panic!("tgId {}: unknown group kind {other:?}", group["tgId"]),
    }
}

/// True for a group that needs the `acvp-internal` hooks when this build does not have them.
fn needs_hooks(kind: Kind) -> bool {
    matches!(kind, Kind::Internal | Kind::ExternalMu) && !cfg!(feature = "acvp-internal")
}

fn load(name: &str) -> Value {
    let path = format!("./tests/nist_vectors/{name}/internalProjection.json");
    let vectors = fs::read_to_string(&path).expect("Unable to read file");
    serde_json::from_str(&vectors).unwrap()
}

fn groups(doc: &Value) -> &Vec<Value> { doc["testGroups"].as_array().expect("testGroups") }

fn cases(group: &Value) -> &Vec<Value> { group["tests"].as_array().expect("tests") }

/// Fails on a group field that this harness does not know, and on any `testType` but AFT.
fn check_group(group: &Value, known: &[&str]) {
    for key in group.as_object().expect("group").keys() {
        assert!(known.contains(&key.as_str()), "tgId {}: unknown group field {key}", group["tgId"]);
    }
    assert_eq!(group["testType"], "AFT", "tgId {}: testType", group["tgId"]);
}

fn hex(v: &Value, key: &str, loc: &str) -> Vec<u8> {
    decode(v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))).unwrap()
}

fn get_ph(hashname: &str, message: &[u8]) -> Result<(&'static [u8], Box<[u8]>), &'static str> {
    match hashname {
        "SHA2-224" => Ok((&pre_hash::SHA2_224, Sha224::digest(message).as_slice().into())),
        "SHA2-256" => Ok((&pre_hash::SHA2_256, Sha256::digest(message).as_slice().into())),
        "SHA2-384" => Ok((&pre_hash::SHA2_384, Sha384::digest(message).as_slice().into())),
        "SHA2-512" => Ok((&pre_hash::SHA2_512, Sha512::digest(message).as_slice().into())),
        "SHA2-512/224" => Ok((&pre_hash::SHA2_512_224, Sha512_224::digest(message).as_slice().into())),
        "SHA2-512/256" => Ok((&pre_hash::SHA2_512_256, Sha512_256::digest(message).as_slice().into())),

        "SHA3-224" => Ok((&pre_hash::SHA3_224, Sha3_224::digest(message).as_slice().into())),
        "SHA3-256" => Ok((&pre_hash::SHA3_256, Sha3_256::digest(message).as_slice().into())),
        "SHA3-384" => Ok((&pre_hash::SHA3_384, Sha3_384::digest(message).as_slice().into())),
        "SHA3-512" => Ok((&pre_hash::SHA3_512, Sha3_512::digest(message).as_slice().into())),

        "SHAKE-128" => Ok((&pre_hash::SHAKE_128, {
            let mut ret = [0u8; 32];
            let mut hasher = Shake128::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut ret);
            ret.into()
        })),
        "SHAKE-256" => Ok((&pre_hash::SHAKE_256, {
            let mut ret = [0u8; 64];
            let mut hasher = Shake256::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut ret);
            ret.into()
        })),
        &_ => Err("unknown digest algorithm"),
    }
}

#[test]
fn test_keygen() {
    let v = load("ML-DSA-keyGen-FIPS204");
    let mut tally = Tally::new(&v);

    for test_group in groups(&v) {
        check_group(test_group, &["parameterSet", "testType", "tests", "tgId"]);
        let set = test_group["parameterSet"].as_str().expect("parameterSet");
        for test in cases(test_group) {
            let loc = format!("{set} tgId={} tcId={}", test_group["tgId"], test["tcId"]);
            let seed: [u8; 32] = hex(test, "seed", &loc).try_into().unwrap();
            let pk_exp = hex(test, "pk", &loc);
            let sk_exp = hex(test, "sk", &loc);

            macro_rules! runtest {
                ($pc:ident) => {{
                    let (pk_act, sk_act) = $pc::KG::keygen_from_seed(&seed);
                    assert_eq!(pk_exp, pk_act.into_bytes(), "{loc}");
                    assert_eq!(sk_exp, sk_act.into_bytes(), "{loc}");
                }};
            }
            tally.count(dispatch!(set, runtest));
        }
    }
    tally.finish("keyGen");
}

#[test]
fn test_siggen() {
    let v = load("ML-DSA-sigGen-FIPS204");
    let mut tally = Tally::new(&v);

    for test_group in groups(&v) {
        check_group(test_group, &[
            "cornerCase", "deterministic", "externalMu", "parameterSet", "preHash",
            "signatureInterface", "testType", "tests", "tgId",
        ]);
        let set = test_group["parameterSet"].as_str().expect("parameterSet");
        let kind = kind_of(test_group);
        let tg_deterministic = test_group["deterministic"].as_bool().unwrap();
        for test in cases(test_group) {
            if needs_hooks(kind) {
                tally.hook_skipped += 1;
                continue;
            }
            let loc = format!("{set} tgId={} tcId={}", test_group["tgId"], test["tcId"]);
            let sk_bytes = hex(test, "sk", &loc);
            let pk_bytes = hex(test, "pk", &loc);
            let sig_exp = hex(test, "signature", &loc);
            let seed = test["rnd"].as_str();
            assert_eq!(seed.is_none(), tg_deterministic, "{loc} rnd");
            let seed: [u8; 32] = match seed {
                None => [0u8; 32],
                Some(s) => decode(s).unwrap().try_into().unwrap(),
            };
            let mut rnd = TestRng::new();
            rnd.push(&seed);

            macro_rules! runtest {
                ($pc:ident) => {{
                    let sk = $pc::PrivateKey::try_from_bytes(sk_bytes.clone().try_into().unwrap()).unwrap();
                    let pk2 = sk.get_public_key();
                    assert_eq!(pk_bytes, pk2.into_bytes(), "{loc}");
                    let pk1 = $pc::PublicKey::try_from_bytes(pk_bytes.clone().try_into().unwrap()).unwrap();
                    let sig: [u8; $pc::SIG_LEN] = sig_exp.clone().try_into().unwrap();
                    let (sig_act, verified) = match kind {
                        Kind::Pure => {
                            let message = hex(test, "message", &loc);
                            let context = hex(test, "context", &loc);
                            (sk.try_sign_with_rng(&mut rnd, &message, &context).unwrap(),
                             pk1.verify(&message, &sig, &context))
                        }
                        Kind::PreHash => {
                            let message = hex(test, "message", &loc);
                            let context = hex(test, "context", &loc);
                            let (hash_oid, digest) = get_ph(test["hashAlg"].as_str().unwrap(), &message).unwrap();
                            (sk.try_hash_sign_with_rng(&mut rnd, &digest, &context, &hash_oid).unwrap(),
                             pk1.hash_verify(&digest, &sig, &context, &hash_oid))
                        }
                        #[cfg(feature = "acvp-internal")]
                        Kind::Internal => {
                            let message = hex(test, "message", &loc);
                            (sk.sign_internal(&mut rnd, &message, !tg_deterministic).unwrap(),
                             pk1.verify_internal(&message, &sig))
                        }
                        #[cfg(feature = "acvp-internal")]
                        Kind::ExternalMu => {
                            let mu: [u8; 64] = hex(test, "mu", &loc).try_into().unwrap();
                            (sk.sign_mu(&mut rnd, &mu, !tg_deterministic).unwrap(),
                             pk1.verify_mu(&mu, &sig))
                        }
                        #[cfg(not(feature = "acvp-internal"))]
                        Kind::Internal | Kind::ExternalMu => unreachable!("skipped above"),
                    };
                    assert_eq!(sig_exp, sig_act, "{loc}");
                    assert!(verified, "{loc} verify");
                }};
            }
            tally.count(dispatch!(set, runtest));
        }
    }
    tally.finish("sigGen");
}

#[test]
fn test_sigver() {
    let v = load("ML-DSA-sigVer-FIPS204");
    let mut tally = Tally::new(&v);

    for test_group in groups(&v) {
        check_group(test_group, &[
            "externalMu", "parameterSet", "preHash", "signatureInterface", "testType", "tests", "tgId",
        ]);
        let set = test_group["parameterSet"].as_str().expect("parameterSet");
        let kind = kind_of(test_group);
        for test in cases(test_group) {
            if needs_hooks(kind) {
                tally.hook_skipped += 1;
                continue;
            }
            let loc = format!("{set} tgId={} tcId={}", test_group["tgId"], test["tcId"]);
            let signature = hex(test, "signature", &loc);
            let pk_bytes = hex(test, "pk", &loc);
            let test_passed = test["testPassed"].as_bool().unwrap();

            macro_rules! runtest {
                ($pc:ident) => {{
                    let pk = $pc::PublicKey::try_from_bytes(pk_bytes.clone().try_into().unwrap()).unwrap();
                    // A signature of the wrong length fails to verify.
                    let res = match signature.as_slice().try_into() {
                        Err(_) => false,
                        Ok(sig) => match kind {
                            Kind::Pure => {
                                let message = hex(test, "message", &loc);
                                pk.verify(&message, sig, &hex(test, "context", &loc))
                            }
                            Kind::PreHash => {
                                let message = hex(test, "message", &loc);
                                let (hash_oid, digest) = get_ph(test["hashAlg"].as_str().unwrap(), &message).unwrap();
                                pk.hash_verify(&digest, sig, &hex(test, "context", &loc), &hash_oid)
                            }
                            #[cfg(feature = "acvp-internal")]
                            Kind::Internal => pk.verify_internal(&hex(test, "message", &loc), sig),
                            #[cfg(feature = "acvp-internal")]
                            Kind::ExternalMu => {
                                let mu: [u8; 64] = hex(test, "mu", &loc).try_into().unwrap();
                                pk.verify_mu(&mu, sig)
                            }
                            #[cfg(not(feature = "acvp-internal"))]
                            Kind::Internal | Kind::ExternalMu => unreachable!("skipped above"),
                        },
                    };
                    assert_eq!(res, test_passed, "{loc} ({})", test["reason"]);
                }};
            }
            tally.count(dispatch!(set, runtest));
        }
    }
    tally.finish("sigVer");
}

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Link flags for the shared library. Choose them by the target, from Cargo's CARGO_CFG_*
    // variables: `cfg!` in a build script describes the build machine, so cross builds got the
    // wrong flags.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let family = |f: &str| target_family.split(',').any(|x| x == f);
    if target_vendor == "apple" {
        // macOS and iOS: an @rpath install name instead of an ELF SONAME
        println!("cargo:rustc-cdylib-link-arg=-shared");
        println!("cargo:rustc-cdylib-link-arg=-dynamiclib");
        println!("cargo:rustc-cdylib-link-arg=-install_name");
        println!("cargo:rustc-cdylib-link-arg=@rpath/libfips204.dylib");
    } else if target_os == "android" {
        // An APK can only hold lib*.so files, so the SONAME carries no version
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libfips204.so");
    } else if family("unix") && !family("wasm") {
        // ELF: the SONAME carries the crate's major version
        let major = env::var("CARGO_PKG_VERSION_MAJOR").unwrap();
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libfips204.so.{major}");
    }
    // Windows and WebAssembly: no extra flags

    // Write minimal pkg-config file:
    let out_dir = env::var("OUT_DIR").unwrap();
    let libname = "fips204";
    let mut desc = env::var("CARGO_PKG_DESCRIPTION").unwrap();
    // strip beginning text:
    let begin_text = "C shared library exposing ";
    assert!(desc.starts_with(begin_text));
    desc.replace_range(..begin_text.len(), "");
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let url = env::var("CARGO_PKG_REPOSITORY").unwrap();
    let pc_dest_path = Path::new(&out_dir).join(format!("{libname}.pc"));

    fs::write(
        pc_dest_path,
        format!(
            "Name: {libname}
Description: {desc}
Version: {version}
URL: {url}
Libs: -l{libname}
"
        ),
    )
    .unwrap()
}

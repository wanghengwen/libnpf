//! Finds or builds libnpf.
//!
//! - `NPF_LIB_DIR`: link the library already built there (with `NPF_INCLUDE_DIR`
//!   for npf.h, default `$NPF_LIB_DIR/../include`). Static `libnpf.a` when it is
//!   there, else the shared library; `NPF_LINK=static|dylib` chooses.
//! - Otherwise libnpf is built with CMake from `NPF_SRC_DIR` (default: this
//!   repository, three levels up) in Release, without its tests and examples.
//!   On Linux the static libnpf.a is linked (one object, only npf.h's symbols
//!   global); elsewhere the shared library.
//!
//! `NPF_CMAKE_ARGS`: extra `-DKEY=VALUE` options for that build, space separated.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    for v in [
        "NPF_LIB_DIR",
        "NPF_INCLUDE_DIR",
        "NPF_LINK",
        "NPF_SRC_DIR",
        "NPF_CMAKE_ARGS",
    ] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let (lib_dir, include_dir) = match env::var_os("NPF_LIB_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let inc = env::var_os("NPF_INCLUDE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| dir.join("../include"));
            (dir, inc)
        }
        None => build_from_source(&manifest, &target_os),
    };

    let static_lib = lib_dir.join("libnpf.a");
    let link_static = match env::var("NPF_LINK").as_deref() {
        Ok("static") => true,
        Ok("dylib") => false,
        _ => target_os == "linux" && static_lib.exists(),
    };
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    if link_static {
        println!("cargo:rustc-link-lib=static=npf");
        // libnpf.a (Linux only) needs just the C library and pthreads
        println!("cargo:rustc-link-lib=pthread");
    } else {
        println!("cargo:rustc-link-lib=dylib=npf");
    }
    println!("cargo:include={}", include_dir.display());
    println!("cargo:lib={}", lib_dir.display());

    // layout check table for tests/layout.rs: the C compiler's view of npf.h
    println!("cargo:rerun-if-changed=csrc/layout.c");
    cc::Build::new()
        .file(manifest.join("csrc/layout.c"))
        .include(&include_dir)
        .compile("npf_sys_layout");
}

fn build_from_source(manifest: &Path, target_os: &str) -> (PathBuf, PathBuf) {
    let src = env::var_os("NPF_SRC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../.."));
    let src = src
        .canonicalize()
        .unwrap_or_else(|e| panic!("libnpf source {}: {e}", src.display()));
    if !src.join("include/npf.h").exists() {
        panic!(
            "{} is not the libnpf source (no include/npf.h); set NPF_SRC_DIR or NPF_LIB_DIR",
            src.display()
        );
    }
    for d in ["CMakeLists.txt", "include", "src", "third_party", "cmake"] {
        println!("cargo:rerun-if-changed={}", src.join(d).display());
    }

    let mut cfg = cmake::Config::new(&src);
    cfg.profile("Release")
        .define("NPF_BUILD_LIB", "ON")
        .define("NPF_BUILD_TESTS", "OFF")
        .define("NPF_BUILD_EXAMPLES", "OFF");
    if let Ok(extra) = env::var("NPF_CMAKE_ARGS") {
        for a in extra.split_whitespace() {
            let a = a.strip_prefix("-D").unwrap_or(a);
            let (k, v) = a.split_once('=').unwrap_or((a, "ON"));
            cfg.define(k, v);
        }
    }
    let out = cfg.build();
    let lib = if out.join("lib64").exists() && !out.join("lib").exists() {
        out.join("lib64")
    } else {
        out.join("lib")
    };
    if target_os == "windows" {
        // npf.dll is installed in bin/: the program needs it next to it or on PATH
        println!("cargo:rustc-env=NPF_DLL_DIR={}", out.join("bin").display());
    }
    (lib, out.join("include"))
}

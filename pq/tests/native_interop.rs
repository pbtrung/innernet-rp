//! Real, independently implemented primitives. No network or kernel effects.
use std::{path::Path, process::Command};

#[test]
fn independent_openssl_and_leancrypto_endpoints() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("crypto-interop");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/interop.c");
    let flags = Command::new("pkg-config")
        .args(["--cflags", "--libs", "leancrypto", "openssl"])
        .output()
        .unwrap();
    assert!(flags.status.success());
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(compiler)
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .args(String::from_utf8(flags.stdout).unwrap().split_whitespace())
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(status.success(), "independent oracle must compile");
    assert!(Command::new(executable).status().unwrap().success());
}

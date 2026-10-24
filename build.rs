#[path = "src/build_metadata.rs"]
mod build_metadata;
use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/build_metadata.rs");
    println!("cargo:rerun-if-env-changed=SBXR_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=RUSTC");
    // Always override inherited values. Unstamped local/debug builds are not
    // released identity, even if someone supplies this internal environment key.
    println!("cargo:rustc-env=SBXR_RETAINED_BUILD_COMMIT=");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let Some(commit) = env::var_os("SBXR_BUILD_COMMIT") else {
        fs::write(out.join("sbxr-build.json"), []).expect("development build metadata");
        return;
    };
    let commit = commit.to_str().expect("SBXR_BUILD_COMMIT must be ASCII");
    let target = env::var("TARGET").expect("Cargo target");
    assert_eq!(
        env::var("PROFILE").as_deref(),
        Ok("release"),
        "released SBXR identity requires release profile"
    );
    let metadata = build_metadata::metadata(commit, &target).expect(
        "released SBXR identity requires lowercase source commit and supported Linux musl target",
    );
    let compiler = Command::new(env::var_os("RUSTC").expect("Cargo RUSTC"))
        .arg("--version")
        .output()
        .expect("inspect actual Rust compiler");
    assert!(
        compiler.status.success()
            && std::str::from_utf8(&compiler.stdout).ok().map(str::trim)
                == Some(
                    std::str::from_utf8(build_metadata::COMPILER_COMMENT)
                        .expect("compiler comment")
                        .replacen("rustc version ", "rustc ", 1)
                        .as_str()
                ),
        "released SBXR identity requires the pinned compiler"
    );
    let script = out.join("sbxr-build.ld");
    fs::write(&script, linker_script(&metadata)).expect("retained linker statement");
    fs::write(out.join("sbxr-build.json"), &metadata).expect("loaded build statement");
    println!("cargo:rustc-env=SBXR_RETAINED_BUILD_COMMIT={commit}");
    println!("cargo:rustc-link-arg-bin=sbxr=-Wl,-T,{}", script.display());
}

/// The linker supplies the section contents directly: no unsafe Rust attributes,
/// object manipulation or external assembler dependency. Explicit BYTE contents
/// survive section garbage collection. GNU ld and lld support INSERT AFTER.
pub fn linker_script(bytes: &[u8]) -> String {
    let mut script = String::from("SECTIONS { .sbxr.rust : {\n");
    for byte in bytes {
        script.push_str(&format!("BYTE(0x{byte:02x});\n"));
    }
    script.push_str("} } INSERT AFTER .rodata;\n");
    script
}

//! Loaded structural build statement. Authentication remains the independent
//! release acquisition/Sigstore boundary; this module never produces trust.
use crate::build_metadata;
const LOADED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sbxr-build.json"));
/// Only the controlled release build emits both canonical metadata and the ELF
/// section. Caller must separately authenticate the complete installed bytes.
pub fn compiled_commit() -> Option<&'static str> {
    if cfg!(debug_assertions) || !cfg!(all(target_os = "linux", target_env = "musl")) {
        return None;
    }
    let commit = env!("SBXR_RETAINED_BUILD_COMMIT");
    let target = if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        return None;
    };
    let expected = build_metadata::metadata(commit, target)?;
    (LOADED == expected).then_some(commit)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn development_build_has_no_released_identity() {
        assert!(compiled_commit().is_none());
    }
}

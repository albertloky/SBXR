//! Canonical structural statement shared by the build script and verifier.
//! This describes compiler inputs; it cannot authenticate an artifact.
pub const COMPILER: &str = "rustc 1.90.0";
pub const COMPILER_COMMENT: &[u8] = b"rustc version 1.90.0 (1159e78c4 2025-09-14)";
pub fn metadata(commit: &str, target: &str) -> Option<Vec<u8>> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(
            target,
            "x86_64-unknown-linux-musl" | "aarch64-unknown-linux-musl"
        )
    {
        return None;
    }
    Some(format!("{{\"schema\":\"sbxr-rust-artifact-v1\",\"repository\":\"albertloky/SBXR\",\"package\":\"sbxr\",\"compiler\":\"{COMPILER}\",\"target\":\"{target}\",\"profile\":\"release\",\"commit\":\"{commit}\"}}").into_bytes())
}

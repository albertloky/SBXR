//! Structural metadata tests; synthetic bytes grant no acquisition trust.
use sbxr::release_identity::{Architecture, rust_artifact_metadata};
#[test]
fn canonical_build_statement_is_target_bound_and_rejects_injected_source_text() {
    for arch in [Architecture::Amd64, Architecture::Arm64] {
        let bytes = rust_artifact_metadata(&"a".repeat(40), arch).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["target"], arch.rust_target());
        assert_eq!(value["commit"], "a".repeat(40));
        assert_eq!(value["compiler"], "rustc 1.90.0");
        assert_eq!(value["profile"], "release");
        assert!(!bytes.contains(&b'\n'));
    }
    for invalid in [
        "A".repeat(40),
        "g".repeat(40),
        "a".repeat(39),
        format!("{}\"", "a".repeat(39)),
        "".into(),
    ] {
        assert!(rust_artifact_metadata(&invalid, Architecture::Amd64).is_err());
    }
    assert!(
        sbxr::build_identity::compiled_commit().is_none(),
        "offline debug builds must never pass released-build admission"
    );
}

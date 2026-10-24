#![forbid(unsafe_code)]
use artifact_trust::SelectionBudget;
use artifact_trust::TrustError;
use host::{
    HostError,
    process::{Cancellation, CommandOutput, CommandRunner, Query},
};
use package_acquisition::*;
use sbxr::{artifact_trust, host, package_acquisition, server_configuration};
use std::{
    io::{self, Cursor, Read},
    time::Instant,
};

const KEY: &[u8] = include_bytes!("testdata/package_acquisition/sagernet.asc");
const DEB: &[u8] = include_bytes!("testdata/package_acquisition/sing-box_1.14.3_amd64.deb");
const INDEX: &[u8] = include_bytes!("testdata/package_acquisition/Packages");

#[test]
fn genuine_public_pinned_material_is_accepted_without_executing_it() {
    let key = include_bytes!("testdata/package_acquisition/sagernet.asc").to_vec();
    let deb = include_bytes!("testdata/package_acquisition/sing-box_1.14.3_amd64.deb").to_vec();
    let verified = VerifiedPackage::verify(key, deb, &SelectionBudget::new()).unwrap();
    assert_eq!(
        verified.key_sha256(),
        server_configuration::PINNED_SING_BOX.signing_key_sha256
    );
    assert_eq!(verified.deb().len(), 32_297_878);
    assert_eq!(verified.identity(), &server_configuration::PINNED_SING_BOX);
    assert_eq!(verified.key(), KEY);
    let (key, deb) = verified.into_parts();
    assert_eq!(key, KEY);
    assert_eq!(deb, DEB);
}

struct Frozen {
    calls: usize,
    bad_key: bool,
    bad_deb: bool,
}
impl PackageTransport for Frozen {
    fn get(
        &mut self,
        request: &PackageRequest,
        _: &SelectionBudget,
    ) -> Result<PackageResponse, TrustError> {
        let bytes = match self.calls {
            0 => {
                assert_eq!(request.url(), "https://sing-box.app/gpg.key");
                KEY
            }
            1 => {
                assert_eq!(
                    request.url(),
                    "https://deb.sagernet.org/dists/*/*/binary-amd64/Packages"
                );
                INDEX
            }
            2 => {
                assert_eq!(
                    request.url(),
                    "https://deb.sagernet.org/files/ver_Gz0vP/sing-box_1.14.3_linux_amd64.deb"
                );
                DEB
            }
            _ => panic!("unexpected request"),
        };
        self.calls += 1;
        let mut bytes = bytes.to_vec();
        if self.calls == 1 && self.bad_key || self.calls == 3 && self.bad_deb {
            bytes[0] ^= 1;
        }
        Ok(PackageResponse::new(200, Cursor::new(bytes)))
    }
}
#[test]
fn acquired_public_bytes_remain_pinned_through_the_real_verifier() {
    let mut source = Frozen {
        calls: 0,
        bad_key: false,
        bad_deb: false,
    };
    let result = acquire(&mut source, &SelectionBudget::new()).unwrap();
    assert_eq!(source.calls, 3);
    assert_eq!(result.deb(), DEB);
    let mut source = Frozen {
        calls: 0,
        bad_key: true,
        bad_deb: false,
    };
    assert!(acquire(&mut source, &SelectionBudget::new()).is_err());
    assert_eq!(
        source.calls, 1,
        "do not fetch metadata with an untrusted key"
    );
    let mut source = Frozen {
        calls: 0,
        bad_key: false,
        bad_deb: true,
    };
    assert!(acquire(&mut source, &SelectionBudget::new()).is_err());
    assert_eq!(source.calls, 3);
}
#[test]
fn wrong_lengths_and_same_length_package_or_key_tampering_refuse() {
    for key in [
        Vec::new(),
        vec![0; MAX_KEY_BYTES + 1],
        KEY[..KEY.len() - 1].to_vec(),
    ] {
        assert!(VerifiedPackage::verify(key, DEB.to_vec(), &SelectionBudget::new()).is_err());
    }
    let mut key = KEY.to_vec();
    key[100] ^= 1;
    assert!(VerifiedPackage::verify(key, DEB.to_vec(), &SelectionBudget::new()).is_err());
    for deb in [
        Vec::new(),
        DEB[..DEB.len() - 1].to_vec(),
        [DEB, b"\n"].concat(),
    ] {
        assert!(VerifiedPackage::verify(KEY.to_vec(), deb, &SelectionBudget::new()).is_err());
    }
    let mut deb = DEB.to_vec();
    let end = deb.len() - 1;
    deb[end] ^= 1;
    assert!(VerifiedPackage::verify(KEY.to_vec(), deb, &SelectionBudget::new()).is_err());
}
#[test]
fn mutable_index_can_only_locate_the_exact_pinned_identity() {
    let original = std::str::from_utf8(INDEX).unwrap();
    let request = package_request(INDEX, &SelectionBudget::new()).unwrap();
    assert_eq!(request.max_bytes(), DEB.len());
    let unknown = original.replace("1.14.3", "1.14.4");
    assert!(package_request(unknown.as_bytes(), &SelectionBudget::new()).is_err());
    for (from, to) in [
        ("Architecture: amd64", "Architecture: arm64"),
        ("Size: 32297878", "Size: 32297879"),
        ("SHA256: ed7", "SHA256: aa7"),
        ("Package: sing-box", "Package: sing-box-beta"),
        ("Filename: files/", "Filename: https://evil.invalid/"),
        ("Filename: files/", "Filename: ../files/"),
        ("Filename: files/", "Filename: files/../"),
        ("Filename: files/", "Filename: files/%2e%2e/"),
        ("Filename: files/", "Filename: files//"),
        (".deb\n", ".deb?download=1\n"),
        (".deb\n", ".deb#fragment\n"),
        ("Version: 1.14.3", "Version: 1.14.3\nVersion: 1.14.3"),
        ("Version: 1.14.3", "Version: 1.14.3\n continuation"),
        ("Package: sing-box", "Package: sing-box\r"),
    ] {
        assert!(
            package_request(
                original.replace(from, to).as_bytes(),
                &SelectionBudget::new()
            )
            .is_err(),
            "{to}"
        );
    }
    assert!(
        package_request(
            format!("{original}\n{original}").as_bytes(),
            &SelectionBudget::new()
        )
        .is_err()
    );
    assert!(package_request(&vec![b'a'; MAX_INDEX_BYTES + 1], &SelectionBudget::new()).is_err());
    assert!(package_request(b"\xff", &SelectionBudget::new()).is_err());
    assert!(package_request(b"", &SelectionBudget::new()).is_err());
    let request = package_request(
        format!("Package: other\nVersion: 1\n\n{original}").as_bytes(),
        &SelectionBudget::new(),
    )
    .unwrap();
    assert_eq!(
        request.url(),
        package_request(INDEX, &SelectionBudget::new())
            .unwrap()
            .url()
    );
}
#[test]
fn redirect_authorization_is_fixed_before_any_followup_get() {
    let key = PackageRequest::signing_key();
    assert!(key.permits_redirect("https://deb.sagernet.org/gpg.key", 1));
    let deb = package_request(INDEX, &SelectionBudget::new()).unwrap();
    let cdn = "https://gemfury.s3-accelerate.dualstack.amazonaws.com/gems/public/sing_box_1_14_3_linux_amd64_deb?X-Amz-Signature=example";
    assert!(deb.permits_redirect(cdn, 1));
    for hops in [0, 5] {
        assert!(!deb.permits_redirect(cdn, hops));
    }
    for bad in [
        "http://deb.sagernet.org/gpg.key",
        "https://deb.sagernet.org:444/gpg.key",
        "https://user@deb.sagernet.org/gpg.key",
        "https://deb.sagernet.org/gpg.key#fragment",
        "https://deb.sagernet.org.evil/gpg.key",
        "https://127.0.0.1/gpg.key",
        "https://deb.sagernet.org/gpg.key\n",
        "https://deb.sagernet.org\\@evil/gpg.key",
        "https://deb.sagernet.org/gpg.key?key=2",
    ] {
        assert!(!key.permits_redirect(bad, 1), "{bad}");
    }
    for bad in [
        cdn.replace("https:", "http:"),
        cdn.replace("amazonaws.com/", "amazonaws.com.evil/"),
        cdn.replace("linux_amd64", "linux_arm64"),
        cdn.replace("https://", "https://user@"),
        format!("{cdn}#fragment"),
    ] {
        assert!(!deb.permits_redirect(&bad, 1));
    }
    assert!(!PackageRequest::index().permits_redirect(cdn, 1));
}
struct ResponseSource {
    kind: u8,
    calls: usize,
}
struct BadRead;
impl Read for BadRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::ConnectionReset.into())
    }
}
impl PackageTransport for ResponseSource {
    fn get(
        &mut self,
        _: &PackageRequest,
        budget: &SelectionBudget,
    ) -> Result<PackageResponse, TrustError> {
        self.calls += 1;
        match self.kind {
            0 => Ok(PackageResponse::new(200, io::repeat(0))),
            1 => Ok(PackageResponse::new(503, Cursor::new(KEY))),
            2 => Ok(PackageResponse::new(200, BadRead)),
            3 => {
                budget.cancel();
                Ok(PackageResponse::new(200, Cursor::new(KEY)))
            }
            _ => Err(TrustError::Unavailable),
        }
    }
}
#[test]
fn transport_errors_status_and_unbounded_readers_fail_closed() {
    for kind in 0..=4 {
        let mut source = ResponseSource { kind, calls: 0 };
        assert!(acquire(&mut source, &SelectionBudget::new()).is_err());
        assert_eq!(source.calls, 1);
    }
    for budget in [SelectionBudget::until(Instant::now()), {
        let b = SelectionBudget::new();
        b.cancel();
        b
    }] {
        let mut source = ResponseSource { kind: 0, calls: 0 };
        assert!(matches!(
            acquire(&mut source, &budget),
            Err(TrustError::Interrupted)
        ));
        assert_eq!(source.calls, 0);
    }
}
struct PackageFacts {
    code: i32,
    package: &'static [u8],
    hold_code: i32,
    hold: &'static [u8],
}
impl CommandRunner for PackageFacts {
    fn query(&self, query: Query, _: &Cancellation) -> Result<CommandOutput, HostError> {
        match query {
            Query::Package => CommandOutput::completed(self.code, self.package.to_vec()),
            Query::Hold => CommandOutput::completed(self.hold_code, self.hold.to_vec()),
            _ => panic!("unexpected query"),
        }
    }
}
#[test]
fn dpkg_hold_and_apt_hold_remain_independent_facts() {
    for (package, hold, expected_package, expected_hold) in [
        (
            b"1.14.3 amd64 hi".as_slice(),
            b"sing-box".as_slice(),
            true,
            true,
        ),
        (b"1.14.3 amd64 hi", b"", true, false),
        (b"1.14.3 amd64 ii", b"sing-box", false, true),
        (
            b"1.14.3 amd64 iU",
            b"not-sing-box\nsing-box-beta",
            false,
            false,
        ),
    ] {
        let facts = PackageFacts {
            code: 0,
            package,
            hold_code: 0,
            hold,
        };
        let result = inspect_installed(&facts, &Cancellation::new()).unwrap();
        assert!(result.present);
        assert_eq!(result.exact_held_package, expected_package);
        assert_eq!(result.apt_hold, expected_hold);
    }
    let mut facts = PackageFacts {
        code: 1,
        package: b"absent diagnostic",
        hold_code: 0,
        hold: b"sing-box",
    };
    let result = inspect_installed(&facts, &Cancellation::new()).unwrap();
    assert!(!result.present && !result.exact_held_package && result.apt_hold);
    facts.hold_code = 2;
    assert!(inspect_installed(&facts, &Cancellation::new()).is_err());
    let stop = Cancellation::new();
    stop.cancel();
    assert!(matches!(
        inspect_installed(&facts, &stop),
        Err(HostError::Cancelled)
    ));
}
#[test]
fn foreign_or_unobserved_installed_package_is_never_owned() {
    for (code, package) in [
        (0, b"1.14.4 amd64 hi".as_slice()),
        (0, b"1.14.3 arm64 hi"),
        (0, b"1.14.3 amd64 hi extra"),
        (2, b"1.14.3 amd64 hi"),
        (0, b"\xff"),
    ] {
        assert!(
            inspect_installed(
                &PackageFacts {
                    code,
                    package,
                    hold_code: 0,
                    hold: b"sing-box"
                },
                &Cancellation::new()
            )
            .is_err()
        );
    }
    assert_eq!(APT_SOURCE,b"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n");
}

#[test]
fn opaque_verified_package_feeds_real_standard_setup_and_recovery_material() {
    struct SyntheticEntropy(u8);
    impl sbxr::identity_generation::Entropy for SyntheticEntropy {
        fn fill(
            &mut self,
            bytes: &mut [u8],
        ) -> Result<(), sbxr::identity_generation::IdentityError> {
            for b in bytes {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }
    let verified =
        VerifiedPackage::verify(KEY.to_vec(), DEB.to_vec(), &SelectionBudget::new()).unwrap();
    let material =
        sbxr::host::linux::SetupMaterial::from_acquired_package(verified, &mut SyntheticEntropy(0))
            .unwrap();
    assert_eq!(format!("{material:?}"), "Setup material (redacted)");
    let verified =
        VerifiedPackage::verify(KEY.to_vec(), DEB.to_vec(), &SelectionBudget::new()).unwrap();
    let recovered = sbxr::host::linux::SetupMaterial::recover_acquired_package(
        verified,
        include_bytes!("testdata/server_configuration/standard.json"),
    )
    .unwrap();
    assert_eq!(format!("{recovered:?}"), "Setup material (redacted)");
}

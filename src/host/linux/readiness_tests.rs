//! Injected Linux command/filesystem observations; never native admission or effects.
use super::*;

// Exact stdout/code vectors from the 2026-10-26 post-cleanup inventory. These
// are not the original q196 failure-time observations or native authority.
fn captured_queries() -> Vec<(Query, i32, Vec<u8>)> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("testdata/clean-absent-queries.json")).unwrap();
    assert_eq!(rows.len(), QUERIES.len());
    QUERIES
        .iter()
        .zip(rows)
        .map(|(query, row)| {
            assert_eq!(row["query"], format!("{query:?}"));
            (
                *query,
                row["code"].as_i64().unwrap().try_into().unwrap(),
                row["stdout"].as_str().unwrap().as_bytes().to_vec(),
            )
        })
        .collect()
}
#[test]
fn captured_clean_absent_queries_admit_the_installed_software_before_proxy_setup() {
    let root = Root::new();
    let (host, commands, _) = system_host(&root);
    host.runner.transport().backend.borrow_mut().query_overrides = captured_queries();
    let installation = StandardInstallation::new(host, release()).unwrap();
    let review = installation.review(Action::StartSetup);
    assert_eq!(review.status, Status::NotSetUp, "{:?}", review.details);
    assert!(review.prepared.is_some());
    assert!(commands.borrow().iter().all(|c| !c.mutation()));
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}

#[test]
fn clean_installed_refusals_identify_bounded_guards_without_payloads() {
    for (case, expected) in [
        (0, "Platform"),
        (1, "Clock"),
        (2, "Query(Enabled)"),
        (3, "ProxyResources"),
        (4, "InstalledPair"),
        (5, "OwnershipStore"),
        (6, "Recovery"),
    ] {
        let root = Root::new();
        let (mut host, commands, _) = system_host(&root);
        match case {
            0 => host.admission.architecture = "arm64".into(),
            1 => {
                host.runner.transport().backend.borrow_mut().query_overrides =
                    vec![(Query::Clock, 0, b"no\n".to_vec())]
            }
            // Existing Go absent-host fixture uses this vector. It is not a
            // capture of q196's missing raw systemctl results; keep it refused.
            2 => {
                host.runner.transport().backend.borrow_mut().query_overrides =
                    vec![(Query::Enabled, 1, b"not-found\n".to_vec())]
            }
            3 => root.write(CONFIG, b"SECRET-SENTINEL /private/owner-path", 0o640),
            4 => root.write("usr/local/bin/sbxr", b"SECRET-SENTINEL", 0o755),
            5 => root.write(
                "var/lib/sbxr/proxy-ownership.json",
                b"SECRET-SENTINEL",
                0o600,
            ),
            _ => host.runner.transport().backend.borrow_mut().held = true,
        }
        let installation = StandardInstallation::new(host, release()).unwrap();
        let review = installation.review(Action::StartSetup);
        assert_eq!(review.status, Status::ProblemDetected);
        assert!(review.prepared.is_none());
        assert_eq!(review.legal_actions, vec![Action::ViewDetails]);
        let details = review.details.join("\n");
        assert!(
            details.contains(&format!("Readiness guard: {expected};")),
            "{details}"
        );
        for secret in [
            "SECRET-SENTINEL",
            "/private/owner-path",
            root.0.to_str().unwrap(),
        ] {
            assert!(!details.contains(secret), "diagnostic disclosed payload");
        }
        assert!(commands.borrow().iter().all(|c| !c.mutation()));
    }
}

struct CleanSources<'a> {
    root: &'a Root,
    proof: &'a crate::release_acquisition::AuthenticatedInstalled,
    setup_ready: bool,
}
impl<'a> crate::proxyinstallation::OwnerSources<'a> for CleanSources<'_> {
    fn journeys(&self) -> Result<Vec<crate::proxyinstallation::Journey>, HostError> {
        use crate::proxyinstallation::Journey;
        // Mirror native no-record ordering; the unrelated Tunnel factory stays unavailable.
        Ok(vec![Journey::Standard, Journey::Tunnel, Journey::Removal])
    }
    fn open(
        &self,
        journey: crate::proxyinstallation::Journey,
    ) -> Result<Box<dyn crate::proxyinstallation::Interface + 'a>, HostError> {
        use crate::proxyinstallation::{Journey, RemovalInstallation};
        let (mut host, _, _) = system_host(self.root);
        host.runner.transport().backend.borrow_mut().query_overrides = captured_queries();
        match journey {
            Journey::Standard => {
                // Setup-only network/clock facts never authorize removal.
                host.admission.destination_compatible = self.setup_ready;
                Ok(Box::new(StandardInstallation::new(
                    host,
                    self.proof.record().release_identity(),
                )?))
            }
            Journey::Removal => {
                let host = LinuxHost::injected_authenticated(
                    &self.root.0,
                    host.runner,
                    SetupMaterial::for_removal(None)?,
                    InjectedAdmission {
                        public_ipv4: String::new(),
                        destination_compatible: false,
                        tcp443_available: false,
                        ..admission()
                    },
                    self.proof,
                )?;
                Ok(Box::new(RemovalInstallation::new(
                    StandardRemovalHost::new(host)?,
                )))
            }
            _ => Err(HostError::LiveUnavailable),
        }
    }
    fn mode(&self) -> crate::proxyinstallation::ExecutionMode {
        crate::proxyinstallation::ExecutionMode::InjectedHost
    }
}
fn clean_pair(root: &Root) -> crate::release_acquisition::AuthenticatedInstalled {
    let (proof, executable) = crate::release_acquisition::fixture_authenticated();
    root.write("usr/local/bin/sbxr", &executable, 0o755);
    root.write(
        "var/lib/sbxr/installed.json",
        &proof.record().encode().unwrap(),
        0o600,
    );
    proof
}
#[test]
fn clean_installed_owner_admits_setup_and_independent_software_only_removal() {
    use crate::proxyinstallation::{Interface, OwnerInstallation};
    for setup_ready in [true, false] {
        let root = Root::new();
        let proof = clean_pair(&root);
        let mut owner = OwnerInstallation::new(CleanSources {
            root: &root,
            proof: &proof,
            setup_ready,
        });
        for action in [Action::Status, Action::ViewDetails] {
            let review = owner.review(action);
            assert_eq!(
                review.status,
                if setup_ready {
                    Status::NotSetUp
                } else {
                    Status::ProblemDetected
                }
            );
            assert_eq!(
                review.legal_actions.contains(&Action::StartSetup),
                setup_ready
            );
            assert!(review.legal_actions.contains(&Action::CompleteRemoval));
        }
        let removal = owner
            .review(Action::CompleteRemoval)
            .prepared
            .expect("independent software-only removal");
        // No mutation: prove the real removal module admits and honors decline.
        assert_eq!(
            owner.execute(removal, Confirmation::Declined).outcome,
            Outcome::Cancelled
        );
        assert!(root.0.join("usr/local/bin/sbxr").exists());
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
        assert!(
            !root
                .0
                .join(super::super::super::locks::MUTATION_LOCK)
                .exists()
        );
    }
}
#[test]
fn clean_installed_owner_preserves_foreign_and_changed_resources() {
    use crate::proxyinstallation::{Interface, OwnerInstallation};
    for changed_after_review in [false, true] {
        let root = Root::new();
        let proof = clean_pair(&root);
        let mut owner = OwnerInstallation::new(CleanSources {
            root: &root,
            proof: &proof,
            setup_ready: true,
        });
        let prepared =
            changed_after_review.then(|| owner.review(Action::StartSetup).prepared.unwrap());
        let payload = b"SECRET-SENTINEL";
        root.write(CONFIG, payload, 0o640);
        if let Some(prepared) = prepared {
            assert_eq!(
                owner.execute(prepared, Confirmation::Approved).outcome,
                Outcome::Refused
            );
        }
        let review = owner.review(Action::StartSetup);
        assert_eq!(review.status, Status::ProblemDetected);
        assert!(!review.legal_actions.contains(&Action::StartSetup));
        assert!(!review.legal_actions.contains(&Action::CompleteRemoval));
        assert!(review.prepared.is_none());
        assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), payload);
        assert!(root.0.join("usr/local/bin/sbxr").exists());
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    }
}

#[test]
fn clean_installed_unknown_command_results_remain_refused_and_classified() {
    for (query, code, bytes) in [
        (Query::Package, 2, b"SECRET-SENTINEL".as_slice()),
        (Query::Hold, 1, b"SECRET-SENTINEL"),
        (Query::User, 2, b"SECRET-SENTINEL"),
        (Query::Group, 2, b"SECRET-SENTINEL"),
        (Query::Process, 0, b"SECRET-SENTINEL"),
        (Query::Enabled, 0, b"not-found"),
        (Query::Active, 4, b"failed"),
        (Query::LoadState, 0, b"SECRET-SENTINEL"),
        (Query::Listener, 1, b"SECRET-SENTINEL"),
        (Query::UnitOwner, 2, b"SECRET-SENTINEL"),
        (Query::Clock, 1, b"SECRET-SENTINEL"),
    ] {
        let root = Root::new();
        let (host, commands, _) = system_host(&root);
        host.runner.transport().backend.borrow_mut().query_overrides =
            vec![(query, code, bytes.to_vec())];
        let module = StandardInstallation::new(host, release()).unwrap();
        let review = module.review(Action::StartSetup);
        assert_eq!(review.status, Status::ProblemDetected);
        assert!(review.prepared.is_none());
        let diagnostic = review.details.join("\n");
        assert!(
            diagnostic.contains(&format!("Readiness guard: Query({query:?});")),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("SECRET-SENTINEL"));
        assert!(commands.borrow().iter().all(|c| !c.mutation()));
    }
}

#[test]
fn absent_active_exit_requires_exact_corroboration_and_rejects_unknown_states() {
    for (query, code, bytes) in [
        (Query::Active, 4, b"failed\n".as_slice()),
        (Query::Active, 4, b"unknown\n"),
        (Query::Active, 4, b"active\n"),
        (Query::Active, 4, b""),
        (Query::Active, 1, b"inactive\n"),
        (Query::Active, 0, b"inactive\n"),
        (Query::Active, 3, b"active\n"),
        (Query::Enabled, 1, b"disabled\n"),
        (Query::Enabled, 1, b"masked\n"),
        (Query::LoadState, 0, b"loaded\n"),
        (Query::LoadState, 0, b"masked\n"),
        (Query::LoadState, 1, b"not-found\n"),
        (Query::LoadState, 0, b"error\n"),
        (Query::LoadState, 0, b"not-found\nloaded\n"),
    ] {
        let root = Root::new();
        let (host, commands, _) = system_host(&root);
        let mut queries = captured_queries();
        let slot = queries.iter_mut().find(|(q, _, _)| *q == query).unwrap();
        *slot = (query, code, bytes.to_vec());
        host.runner.transport().backend.borrow_mut().query_overrides = queries;
        let installation = StandardInstallation::new(host, release()).unwrap();
        let review = installation.review(Action::StartSetup);
        assert_eq!(review.status, Status::ProblemDetected, "{query:?}");
        assert!(review.prepared.is_none());
        assert!(
            review
                .details
                .iter()
                .any(|d| d.contains("Readiness guard: Query(Active); result: Unsafe."))
        );
        assert!(commands.borrow().iter().all(|c| !c.mutation()));
    }
}
#[test]
fn captured_absent_service_never_bypasses_platform_network_lock_or_transaction_guards() {
    for case in 0..8 {
        let root = Root::new();
        let (mut host, commands, _) = system_host(&root);
        host.runner.transport().backend.borrow_mut().query_overrides = captured_queries();
        match case {
            0 => host.admission.root = false,
            1 => host.admission.architecture = "arm64".into(),
            2 => host.admission.destination_compatible = false,
            3 => host.admission.host_lock_held = false,
            4 => host.admission.package_locks_held = false,
            5 => host.admission.tcp443_available = false,
            6 => root.write("var/lib/sbxr/update.json", b"foreign", 0o600),
            _ => host.admission.public_ipv4 = "127.0.0.1".into(),
        }
        let installation = StandardInstallation::new(host, release()).unwrap();
        let review = installation.review(Action::StartSetup);
        assert_eq!(review.status, Status::ProblemDetected);
        assert!(review.prepared.is_none());
        assert!(commands.borrow().iter().all(|c| !c.mutation()));
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    }
}

#[test]
fn fixed_query_timing_brackets_actual_transport_without_command_payload() {
    let root = Root::new();
    let (host, commands, _) = system_host(&root);
    host.runner.transport().backend.borrow_mut().query_overrides =
        vec![(Query::Active, 7, b"SECRET-SENTINEL /private/path".to_vec())];
    let (result, bytes) =
        crate::host::timing::capture(|| host.runner.query(Query::Active, &Cancellation::new()));
    assert_eq!(result.unwrap().bytes(), b"SECRET-SENTINEL /private/path");
    assert_eq!(commands.borrow().len(), 1);
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("SECRET-SENTINEL") && !text.contains("/private/path"));
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line.strip_prefix("SBXR_NATIVE_PHASE ").unwrap()).unwrap())
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "the actual fixed-query boundary must be measured"
    );
    assert_eq!(rows[0]["phase"], "query-active");
    assert_eq!(rows[0]["event"], "begin");
    assert_eq!(rows[1]["event"], "end");
    assert_eq!(rows[0]["id"], rows[1]["id"]);
}

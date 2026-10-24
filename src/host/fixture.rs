use super::{
    FixtureFault, HostError, Operation,
    filesystem::{Evidence, Kind, ProtectedFs, Resource},
};
use crate::records::{InstalledRecord, OwnershipRecord, ReleaseIdentity, sha256_hex};
use rustix::fs::Mode;
use std::path::Path;

pub const FIXTURE_CONFIGURATION: &[u8] = b"{\"sbxr_fixture_only\":true}\n";
const EXECUTABLE: &[u8] = b"SBXR fixture executable; never run this file.\n";
const MARKER: Resource = Resource {
    path: ".sbxr-fixture-root",
    kind: Kind::File(
        b"SBXR filesystem fixture v1; no real system operations\n",
        Mode::from_raw_mode(0o600),
    ),
};
const APT_SOURCE:&[u8]=b"Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n";
const UNIT: &[u8] = include_bytes!("../records/lock-provision.service");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Id {
    AptKey,
    AptSource,
    Mask,
    PackageArtifact,
    Package,
    Hold,
    Identity,
    ConfigDirectory,
    StateDirectory,
    Configuration,
    Validated,
    Enabled,
    Active,
    LockUnit,
    LockLink,
}
const RESOURCES: &[(Id, Resource)] = &[
    (
        Id::AptKey,
        Resource {
            path: "etc/apt/keyrings/sagernet.asc",
            kind: Kind::File(
                b"FIXTURE: synthetic signing key; not upstream trust material\n",
                Mode::from_raw_mode(0o644),
            ),
        },
    ),
    (
        Id::AptSource,
        Resource {
            path: "etc/apt/sources.list.d/sagernet.sources",
            kind: Kind::File(APT_SOURCE, Mode::from_raw_mode(0o644)),
        },
    ),
    (
        Id::Mask,
        Resource {
            path: ".fixture-state/masked",
            kind: Kind::File(b"masked\n", Mode::from_raw_mode(0o600)),
        },
    ),
    (
        Id::PackageArtifact,
        Resource {
            path: "var/lib/sbxr/sing-box_1.14.3_amd64.deb",
            kind: Kind::File(
                b"FIXTURE: verified-package effect; not a DEB\n",
                Mode::from_raw_mode(0o600),
            ),
        },
    ),
    (
        Id::Package,
        Resource {
            path: ".fixture-state/package",
            kind: Kind::File(
                b"FIXTURE sing-box 1.14.3 amd64\n",
                Mode::from_raw_mode(0o600),
            ),
        },
    ),
    (
        Id::Hold,
        Resource {
            path: ".fixture-state/hold",
            kind: Kind::File(b"sing-box\n", Mode::from_raw_mode(0o600)),
        },
    ),
    (
        Id::Identity,
        Resource {
            path: ".fixture-state/identity",
            kind: Kind::File(b"FIXTURE sing-box user/group\n", Mode::from_raw_mode(0o600)),
        },
    ),
    (
        Id::ConfigDirectory,
        Resource {
            path: "etc/sing-box",
            kind: Kind::Directory(Mode::from_raw_mode(0o755)),
        },
    ),
    (
        Id::StateDirectory,
        Resource {
            path: "var/lib/sing-box",
            kind: Kind::Directory(Mode::from_raw_mode(0o755)),
        },
    ),
    (
        Id::Configuration,
        Resource {
            path: "etc/sing-box/config.json",
            kind: Kind::File(FIXTURE_CONFIGURATION, Mode::from_raw_mode(0o640)),
        },
    ),
    (
        Id::Validated,
        Resource {
            path: ".fixture-state/validated",
            kind: Kind::File(
                b"FIXTURE configuration check accepted\n",
                Mode::from_raw_mode(0o600),
            ),
        },
    ),
    (
        Id::Enabled,
        Resource {
            path: ".fixture-state/enabled",
            kind: Kind::File(b"enabled\n", Mode::from_raw_mode(0o600)),
        },
    ),
    (
        Id::Active,
        Resource {
            path: ".fixture-state/active",
            kind: Kind::File(b"active\n", Mode::from_raw_mode(0o600)),
        },
    ),
    (
        Id::LockUnit,
        Resource {
            path: "etc/systemd/system/sbxr-mutation-lock.service",
            kind: Kind::File(UNIT, Mode::from_raw_mode(0o644)),
        },
    ),
    (
        Id::LockLink,
        Resource {
            path: "etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service",
            kind: Kind::Link("../sbxr-mutation-lock.service"),
        },
    ),
];
fn resource(id: Id) -> Resource {
    RESOURCES
        .iter()
        .find(|(key, _)| *key == id)
        .expect("fixed resource")
        .1
}

/// Verified fixture files only; no observation is a production runtime proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostObservation {
    installed: Evidence,
    executable: Evidence,
    resources: Vec<(Id, Option<Evidence>)>,
}
impl HostObservation {
    fn has(&self, id: Id) -> bool {
        self.resources
            .iter()
            .any(|(key, fact)| *key == id && fact.is_some())
    }
    pub fn empty(&self) -> bool {
        self.resources.iter().all(|(_, fact)| fact.is_none())
    }
    pub fn ready_to_activate(&self) -> bool {
        [
            Id::AptKey,
            Id::AptSource,
            Id::Package,
            Id::Hold,
            Id::Identity,
            Id::ConfigDirectory,
            Id::StateDirectory,
            Id::Configuration,
            Id::Validated,
            Id::LockUnit,
            Id::LockLink,
        ]
        .into_iter()
        .all(|id| self.has(id))
            && !self.has(Id::Mask)
            && !self.has(Id::PackageArtifact)
    }
    pub fn running(&self) -> bool {
        self.ready_to_activate() && self.has(Id::Enabled) && self.has(Id::Active)
    }
    pub(crate) fn service_enabled(&self) -> bool {
        self.has(Id::Enabled)
    }
    pub fn stopped(&self) -> bool {
        !self.has(Id::Active) && !self.has(Id::Enabled)
    }
}

pub struct FixtureHost {
    fs: ProtectedFs,
    fault: Option<FixtureFault>,
}
impl FixtureHost {
    /// Initializes only an existing empty 0700 temporary fixture directory.
    /// The synthetic software pair proves fixture identity, never release trust.
    pub fn create(root: &Path, release: ReleaseIdentity) -> Result<Self, HostError> {
        let fs = ProtectedFs::open(root)?;
        if !fs.empty()? {
            return Err(HostError::Foreign);
        }
        fs.install(MARKER)?;
        fs.install(Resource {
            path: "var/lib/sbxr",
            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
        })?;
        fs.install(Resource {
            path: ".fixture-state",
            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
        })?;
        fs.install_bytes("usr/local/bin/sbxr", EXECUTABLE, Mode::from_raw_mode(0o755))?;
        let installed = InstalledRecord::new(release, 1, "amd64", &sha256_hex(EXECUTABLE))
            .map_err(|_| HostError::Unsafe)?;
        fs.install_bytes(
            "var/lib/sbxr/installed.json",
            &installed.encode().map_err(|_| HostError::Unsafe)?,
            Mode::from_raw_mode(0o600),
        )?;
        Ok(Self { fs, fault: None })
    }
    pub fn open(root: &Path) -> Result<Self, HostError> {
        let fs = ProtectedFs::open(root)?;
        if fs.observe(MARKER)?.is_none() {
            return Err(HostError::Unsafe);
        }
        Ok(Self { fs, fault: None })
    }
    pub fn root(&self) -> &Path {
        self.fs.path()
    }
    pub(crate) fn uid(&self) -> u32 {
        self.fs.uid
    }
    pub fn set_fault(&mut self, fault: Option<FixtureFault>) {
        self.fault = fault;
    }
    pub(crate) fn interrupted(&self, phase: crate::records::SetupPhase) -> bool {
        self.fault == Some(FixtureFault::InterruptAfter(phase))
    }
    pub fn inspect(&self, release: &ReleaseIdentity) -> Result<HostObservation, HostError> {
        if self.fs.observe(MARKER)?.is_none() {
            return Err(HostError::Unsafe);
        }
        let (body, installed) = self
            .fs
            .raw(
                "var/lib/sbxr/installed.json",
                Mode::from_raw_mode(0o600),
                4096,
            )?
            .ok_or(HostError::Unsafe)?;
        let record = InstalledRecord::decode(&body).map_err(|_| HostError::Foreign)?;
        let (bytes, executable) = self
            .fs
            .raw("usr/local/bin/sbxr", Mode::from_raw_mode(0o755), 4096)?
            .ok_or(HostError::Unsafe)?;
        if record.release_identity() != *release
            || record.sequence() != 1
            || record.architecture() != "amd64"
            || record.executable_sha256() != sha256_hex(&bytes)
            || bytes != EXECUTABLE
        {
            return Err(HostError::Foreign);
        }
        let resources = RESOURCES
            .iter()
            .map(|(id, resource)| Ok((*id, self.fs.observe(*resource)?)))
            .collect::<Result<Vec<_>, HostError>>()?;
        Ok(HostObservation {
            installed,
            executable,
            resources,
        })
    }
    /// No command is spawned. Every effect is an exact bound file, directory or
    /// link below the pinned fixture root; foreign values are never replaced.
    pub(crate) fn apply(
        &mut self,
        operation: Operation,
        authority: &OwnershipRecord,
    ) -> Result<(), HostError> {
        if authority.configuration_sha256() != sha256_hex(FIXTURE_CONFIGURATION) {
            return Err(HostError::Foreign);
        }
        let observation = self.inspect(&authority.release_identity())?;
        if self.fault == Some(FixtureFault::FailBefore(operation)) {
            return Err(HostError::Injected);
        }
        use Operation::*;
        let (install, remove): (&[Id], &[Id]) = match operation {
            InstallAptKey => (&[Id::AptKey], &[]),
            InstallAptSource => (&[Id::AptSource], &[]),
            MaskService => (&[Id::Mask, Id::LockUnit, Id::LockLink], &[]),
            InstallPackage => {
                if !observation.has(Id::Mask) {
                    return Err(HostError::Unsafe);
                }
                (
                    &[
                        Id::PackageArtifact,
                        Id::Package,
                        Id::Identity,
                        Id::ConfigDirectory,
                    ],
                    &[Id::PackageArtifact],
                )
            }
            HoldPackage => {
                if !observation.has(Id::Package) {
                    return Err(HostError::Unsafe);
                }
                (&[Id::Hold], &[])
            }
            CreateStateDirectory => (&[Id::StateDirectory], &[]),
            InstallConfiguration => (&[Id::Configuration], &[]),
            ValidateConfiguration => {
                if !observation.has(Id::Configuration) {
                    return Err(HostError::Unsafe);
                }
                (&[Id::Validated], &[])
            }
            UnmaskService => (&[], &[Id::Mask]),
            EnableService => {
                if !observation.ready_to_activate() {
                    return Err(HostError::Unsafe);
                }
                (&[Id::Enabled], &[])
            }
            StartService => {
                if !observation.ready_to_activate() || !observation.has(Id::Enabled) {
                    return Err(HostError::Unsafe);
                }
                (&[Id::Active], &[])
            }
            StopDisableService => (&[], &[Id::Active, Id::Enabled, Id::LockLink, Id::LockUnit]),
            RemovePackageArtifact => (&[], &[Id::PackageArtifact]),
            RemovePackageHold => (&[], &[Id::Hold]),
            RemovePackage => (&[], &[Id::Hold, Id::Package]),
            RemoveConfigurationState => (
                &[],
                &[
                    Id::Validated,
                    Id::Configuration,
                    Id::ConfigDirectory,
                    Id::StateDirectory,
                ],
            ),
            RemovePackageIdentity => (&[], &[Id::Identity]),
            RemoveAptSource => (&[], &[Id::AptSource]),
            RemoveAptKey => (&[], &[Id::AptKey]),
        };
        for id in install {
            self.fs.install(resource(*id))?;
        }
        for id in remove {
            self.fs.remove(resource(*id))?;
        }
        if self.fault == Some(FixtureFault::FailAfter(operation)) {
            return Err(HostError::Injected);
        }
        Ok(())
    }
}

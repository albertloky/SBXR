//! Concrete protected disclosure/compromise Host. Native construction requires
//! supported root:root and authenticated current bytes; tests use explicit roots.
use super::{
    HostError,
    filesystem::ProtectedFs,
    locks::{HostLock, PackageLocks},
    owner_runtime::{NativeIo, OwnerIo, OwnerRuntime},
};
use crate::{
    disclosure as d, durable::OwnershipStore, records::OwnershipRecord,
    release_acquisition::AuthenticatedInstalled,
};
use rustix::fs::Mode;
use std::{cell::RefCell, path::Path, sync::Arc};
pub struct Guard {
    owner: Arc<HostLock>,
    packages: PackageLocks<'static>,
    store: RefCell<OwnershipStore>,
}
pub struct ProtectedDisclosureHost<'a, I> {
    fs: ProtectedFs,
    proof: &'a AuthenticatedInstalled,
    runtime: OwnerRuntime<'a, I>,
}
fn refused(_: impl std::fmt::Debug) -> d::Error {
    d::Error::Authority
}
impl<'a> ProtectedDisclosureHost<'a, NativeIo> {
    pub fn native_unreleased(proof: &'a AuthenticatedInstalled) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        let fs = ProtectedFs::native()?;
        if fs.uid != 0 || fs.gid != 0 {
            return Err(HostError::Foreign);
        }
        Ok(Self {
            fs,
            proof,
            runtime: OwnerRuntime::native_unreleased(proof)?,
        })
    }
}
impl<'a, I: OwnerIo> ProtectedDisclosureHost<'a, I> {
    pub fn injected(
        root: &Path,
        proof: &'a AuthenticatedInstalled,
        io: I,
        address: std::net::SocketAddr,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        Ok(Self {
            fs: ProtectedFs::open(root)?,
            proof,
            runtime: OwnerRuntime::injected(root, proof, io, address)?,
        })
    }
}
impl<I: OwnerIo> d::Host for ProtectedDisclosureHost<'_, I> {
    type Guard = Guard;
    fn owner_uid(&self) -> u32 {
        self.fs.uid
    }
    fn owner_gid(&self) -> u32 {
        self.fs.gid
    }
    fn acquire(&mut self) -> Result<Guard, d::Error> {
        let owner = Arc::new(HostLock::existing(self.fs.path(), self.fs.uid).map_err(refused)?);
        let packages = owner.retain_packages().map_err(refused)?;
        let store = RefCell::new(
            OwnershipStore::open(&self.fs.path().join("var/lib/sbxr"), self.fs.uid)
                .map_err(refused)?,
        );
        let guard = Guard {
            owner,
            packages,
            store,
        };
        self.verify_guard(&guard)?;
        Ok(guard)
    }
    fn verify_guard(&mut self, g: &Guard) -> Result<(), d::Error> {
        if g.owner.root() != self.fs.path() {
            return Err(d::Error::Authority);
        }
        g.owner.verify().map_err(refused)?;
        g.packages.verify().map_err(refused)?;
        self.runtime.installed().map_err(refused)
    }
    fn snapshot(&mut self, g: &Guard) -> Result<crate::client_identity::Snapshot, d::Error> {
        self.verify_guard(g)?;
        let s = g.store.borrow().load().map_err(refused)?;
        Ok(crate::client_identity::Snapshot {
            current: s.current.ok_or(d::Error::Authority)?.bytes().to_vec(),
            staged: s.staged.map(|r| r.bytes().to_vec()),
        })
    }
    fn inspect(&mut self, g: &Guard, r: &OwnershipRecord) -> Result<d::Inspection, d::Error> {
        self.verify_guard(g)?;
        if r.release_identity() != self.proof.record().release_identity() {
            return Err(d::Error::Authority);
        }
        let result = self
            .runtime
            .disclosure_inspection(r, &g.owner)
            .map_err(refused)?;
        self.verify_guard(g)?;
        Ok(result)
    }
    fn read(&mut self, g: &Guard, m: d::Material) -> Result<d::ProtectedFile, d::Error> {
        self.verify_guard(g)?;
        let (path, mode, limit) = match m {
            d::Material::Configuration => ("etc/sing-box/config.json", 0o640, 1 << 20),
            d::Material::SubscriptionToken => (super::subscription::TOKEN, 0o600, 44),
            d::Material::ServingState => (
                super::subscription::STATE,
                0o600,
                crate::records::MAX_RECORD_BYTES,
            ),
        };
        let (bytes, proof) = self
            .fs
            .raw(path, Mode::from_raw_mode(mode), limit)
            .map_err(refused)?
            .ok_or(d::Error::Authority)?;
        self.verify_guard(g)?;
        Ok(d::ProtectedFile::new(
            bytes,
            d::FileProof {
                regular: true,
                uid: self.fs.uid,
                gid: proof.gid,
                mode: u32::from(mode),
                links: 1,
                protected_ancestry: true,
            },
        ))
    }
    fn publish(
        &mut self,
        g: &Guard,
        expected: &[u8],
        next: &OwnershipRecord,
    ) -> Result<(), d::Error> {
        self.verify_guard(g)?;
        g.store
            .borrow_mut()
            .publish(Some(expected), next)
            .map_err(|_| d::Error::Publication)?;
        self.verify_guard(g).map_err(|_| d::Error::Publication)
    }
}

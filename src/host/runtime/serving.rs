//! Concrete Standard HTTP serving with protected files and explicit observations.
//! Runtime authority comes from the Ownership Record, never token/state files.
use super::{material::RuntimeFiles, *};
use crate::{
    records::ServingAuthority,
    release_acquisition::AuthenticatedArchive,
    runtime_handoff::{ServingHost, ServingSandbox, WatchOutcome},
};
use std::{
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    time::{Duration, Instant},
};
pub struct ServingRuntimeHost<'a, E> {
    files: RuntimeFiles<'a>,
    environment: E,
    socket: Option<PathBuf>,
    watch_interval: Duration,
}
impl<'a> ServingRuntimeHost<'a, NativeServingEnvironment> {
    pub(in crate::host) fn native_unreleased(
        proof: &'a crate::host::admission_private::OfflinePrivateAdmission,
    ) -> Result<Self, HostError> {
        proof.require_role(Role::SubscriptionServing)?;
        let files = RuntimeFiles::native_record(proof)?;
        Ok(Self {
            files,
            environment: NativeServingEnvironment,
            socket: None,
            watch_interval: Duration::from_secs(60),
        })
    }
}
impl<'a, E: ServingEnvironment> ServingRuntimeHost<'a, E> {
    pub fn injected(
        root: &Path,
        archive: &'a AuthenticatedArchive,
        environment: E,
        socket: PathBuf,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || !socket.is_absolute() || socket.parent() != Some(root) {
            return Err(HostError::Unsafe);
        }
        Ok(Self {
            files: RuntimeFiles::archive(root, archive)?,
            environment,
            socket: Some(socket),
            watch_interval: Duration::from_secs(60),
        })
    }
    #[cfg(test)]
    pub(super) fn with_fixture_watch_interval(mut self, interval: Duration) -> Self {
        assert!(self.files.fs.path() != Path::new("/"));
        self.watch_interval = interval;
        self
    }
}
pub(super) fn validate_serving_footprint(files: &RuntimeFiles<'_>) -> Result<(), Error> {
    // Exact current Go sandbox footprint. Inaccessible token/staging are
    // checked by the kernel observer; never opened as credential authority.
    const ALLOWED: &[&str] = &[
        "installed.json",
        "proxy-ownership.json",
        ".proxy-ownership.json.next",
        "update.json",
        ".update.json.next",
        ".installed.json.prior",
        ".installed.json.candidate",
        "client-identity-target.json",
        "client-identity-target.json.sbxr-next",
        "subscription-token",
        "subscription-serving.json",
        "subscription-staging",
        "renewal-attempts.json",
        ".renewal-attempts.json.next",
        "renewal-admission.lock",
        "renewal-writer.lock",
        "subscription-https-retired",
        "subscription-serving.json.sbxr-next",
    ];
    let entries = files
        .fs
        .directory_entries("var/lib/sbxr", Mode::from_raw_mode(0o700))
        .map_err(refused)?
        .ok_or(Error::Refused)?;
    if entries.iter().any(|name| !ALLOWED.contains(&name.as_str())) {
        return Err(Error::Refused);
    }
    for path in [
        "var/lib/sbxr/subscription-serving.json.sbxr-next",
        "etc/systemd/system/sbxr-subscription.service.d",
        "usr/lib/systemd/system/sbxr-subscription.service",
        "usr/lib/systemd/system/sbxr-subscription.service.d",
        "etc/systemd/system/service.d",
        "usr/lib/systemd/system/service.d",
    ] {
        if files.fs.metadata(path).map_err(refused)?.is_some() {
            return Err(Error::Refused);
        }
    }
    let path = "etc/systemd/system/multi-user.target.wants/sbxr-subscription.service";
    let short = files.fs.observe(crate::host::filesystem::Resource {
        path,
        kind: crate::host::filesystem::Kind::Link("../sbxr-subscription.service"),
    });
    if !matches!(short, Ok(Some(_))) {
        files
            .fs
            .observe(crate::host::filesystem::Resource {
                path,
                kind: crate::host::filesystem::Kind::Link(
                    "/etc/systemd/system/sbxr-subscription.service",
                ),
            })
            .map_err(refused)?
            .ok_or(Error::Refused)?;
    }
    files.installed()?;
    Ok(())
}
impl<E: ServingEnvironment> ServingHost for ServingRuntimeHost<'_, E> {
    fn acquire_start(&self, context: &StartContext) -> Result<StartLock, Error> {
        runtime_handoff::acquire_serving_start(
            self.files.fs.path(),
            self.files.fs.uid,
            context,
            || self.environment.process(),
            || {
                let stream = if let Some(path) = &self.socket {
                    crate::host::runtime_io::connect_fixture(self.files.fs.path(), path, context)?
                } else {
                    crate::host::runtime_io::connect_native(self.files.fs.path(), context)?
                };
                let uid = self.environment.lender_uid(&stream)?;
                Ok((stream, uid))
            },
        )
    }
    fn installed_identity(
        &self,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<ReleaseIdentity, Error> {
        context.check()?;
        self.files.start(Role::SubscriptionServing, lock, context)?;
        Ok(self.files.record.release_identity())
    }
    fn ownership(&self) -> Result<Vec<u8>, Error> {
        self.files.ownership()
    }
    fn pending_and_final_absent(&self) -> Result<bool, Error> {
        self.files.pending_absent()
    }
    fn validate_material(
        &self,
        record: &OwnershipRecord,
        selected: &ServingAuthority,
    ) -> Result<(), Error> {
        if !selected.is_http() || record.release_identity() != self.files.record.release_identity()
        {
            return Err(Error::Refused);
        }
        validate_serving_footprint(&self.files)
    }
    fn unit(&self) -> Result<Vec<u8>, Error> {
        self.files
            .fs
            .raw(
                "etc/systemd/system/sbxr-subscription.service",
                Mode::from_raw_mode(0o644),
                8192,
            )
            .map_err(refused)?
            .map(|(b, _)| b)
            .ok_or(Error::Refused)
    }
    fn sandbox(&self) -> Result<ServingSandbox, Error> {
        self.environment.sandbox()
    }
    fn public_ipv4(&self, context: &StartContext) -> Result<Ipv4Addr, Error> {
        self.environment.public_ipv4(context)
    }
    fn configuration(&self) -> Result<Vec<u8>, Error> {
        self.files.configuration()
    }
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<TcpListener, Error> {
        if self.files.fs.path() != Path::new("/") && (address != Ipv4Addr::LOCALHOST || port != 0) {
            return Err(Error::Refused);
        }
        if self.files.fs.path() == Path::new("/") && port != 8443 {
            return Err(Error::Refused);
        }
        self.environment.bind_listener(address, port)
    }
    fn watch_public_ipv4(&self, expected: Ipv4Addr, stop: &Cancellation) -> WatchOutcome {
        loop {
            let next = Instant::now() + self.watch_interval;
            while Instant::now() < next {
                if stop.is_cancelled() {
                    return WatchOutcome::Cancelled;
                }
                std::thread::sleep(
                    Duration::from_millis(10).min(next.saturating_duration_since(Instant::now())),
                );
            }
            let context = StartContext::new(stop.clone(), Instant::now() + Duration::from_secs(10));
            let accepted = self
                .environment
                .public_ipv4(&context)
                .is_ok_and(|ip| ip == expected);
            if stop.is_cancelled() {
                return WatchOutcome::Cancelled;
            }
            if !accepted {
                return WatchOutcome::PublicIpv4Failed;
            }
        }
    }
}
#[cfg(test)]
#[path = "serving_tests.rs"]
mod tests;

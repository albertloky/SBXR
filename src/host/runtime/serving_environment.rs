//! Fixed sandbox observations and public-IP probe. No system mutation, /proc
//! fallback, requested process identity, mount or capability changes.
use super::*;
#[cfg(target_os = "linux")]
use crate::runtime_handoff::{PathAccess, SUBSCRIPTION_CGROUP};
use crate::runtime_handoff::{SandboxProcess, ServingSandbox};
use std::{
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
pub trait ServingEnvironment: Sync {
    fn process(&self) -> Result<SandboxProcess, Error>;
    fn sandbox(&self) -> Result<ServingSandbox, Error>;
    fn lender_uid(&self, stream: &UnixStream) -> Result<u32, Error>;
    fn public_ipv4(&self, context: &StartContext) -> Result<Ipv4Addr, Error>;
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<std::net::TcpListener, Error>;
}
pub struct NativeServingEnvironment;
impl ServingEnvironment for NativeServingEnvironment {
    fn process(&self) -> Result<SandboxProcess, Error> {
        #[cfg(target_os = "linux")]
        {
            super::super::linux::require_native_environment().map_err(refused)?;
            let pid = std::process::id();
            let fs = ProtectedFs::native().map_err(refused)?;
            let procs = fs
                .cgroup_bytes(crate::host::owner_runtime::Unit::Subscription, false)
                .map_err(refused)?
                .ok_or(Error::Refused)?;
            if procs.len() >= 4096
                || std::str::from_utf8(&procs).map_err(refused)?.trim() != pid.to_string()
            {
                return Err(Error::Refused);
            }
            // Cargo enables runtime + use-libc-auxv: direct getauxval works
            // with static musl. The weak/dlsym variant cannot prove this path
            // in a static binary; /proc fallback is not admissible here.
            let path = rustix::param::linux_execfn()
                .to_str()
                .map_err(refused)?
                .to_owned();
            Ok(SandboxProcess {
                pid,
                uid: rustix::process::geteuid().as_raw(),
                cgroup: SUBSCRIPTION_CGROUP.into(),
                executable_path: path,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Refused)
        }
    }
    fn sandbox(&self) -> Result<ServingSandbox, Error> {
        #[cfg(target_os = "linux")]
        {
            let process = self.process()?;
            let caps = rustix::thread::capabilities(None).map_err(refused)?;
            let mut ambient = 0;
            // Ubuntu 24.04 supports capability numbers 0..=40. Read the
            // ambient set independently rather than filling an assumed zero.
            for bit in 0..=40 {
                let flag = rustix::thread::CapabilitySet::from_bits_retain(1u64 << bit);
                if rustix::thread::capability_is_in_ambient_set(flag).map_err(refused)? {
                    ambient |= 1u64 << bit;
                }
            }
            let access = |path: &str| match rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(_) => PathAccess::Accessible,
                Err(rustix::io::Errno::ACCESS) => PathAccess::PermissionDenied,
                Err(rustix::io::Errno::NOENT) => PathAccess::Missing,
                Err(_) => PathAccess::Unknown,
            };
            let inaccessible = [
                "/var/lib/sbxr/subscription-token",
                "/var/lib/sbxr/subscription-staging",
                "/proc",
                "/run/systemd",
                "/run/dbus",
            ]
            .map(access);
            let cgroup_procs = ProtectedFs::native()
                .map_err(refused)?
                .cgroup_bytes(crate::host::owner_runtime::Unit::Subscription, false)
                .map_err(refused)?
                .ok_or(Error::Refused)?;
            let proof = ServingSandbox {
                effective_uid: process.uid,
                process,
                capabilities: [
                    caps.effective.bits(),
                    caps.permitted.bits(),
                    caps.inheritable.bits(),
                    ambient,
                ],
                no_new_privileges: rustix::thread::no_new_privs().map_err(refused)?,
                inaccessible,
                cgroup_procs,
            };
            proof.validate()?;
            Ok(proof)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Refused)
        }
    }
    fn lender_uid(&self, stream: &UnixStream) -> Result<u32, Error> {
        #[cfg(target_os = "linux")]
        {
            Ok(rustix::net::sockopt::socket_peercred(stream)
                .map_err(refused)?
                .uid
                .as_raw())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Err(Error::Refused)
        }
    }
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<std::net::TcpListener, Error> {
        super::super::linux::require_native_environment().map_err(refused)?;
        if port != 8443 || !crate::records::ownership_public_ipv4(&address.to_string()) {
            return Err(Error::Refused);
        }
        std::net::TcpListener::bind((address, port)).map_err(refused)
    }
    fn public_ipv4(&self, context: &StartContext) -> Result<Ipv4Addr, Error> {
        context.check()?;
        let budget = crate::artifact_trust::SelectionBudget::until(
            context
                .deadline()
                .min(Instant::now() + Duration::from_secs(10)),
        );
        let done = std::sync::atomic::AtomicBool::new(false);
        struct Finish<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Finish<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        std::thread::scope(|scope| {
            let finished = Finish(&done);
            let watcher = std::thread::Builder::new()
                .name("sbxr-ip-cancel".into())
                .spawn_scoped(scope, || {
                    while !done.load(std::sync::atomic::Ordering::Acquire) {
                        if context.check().is_err() {
                            budget.cancel();
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })
                .map_err(refused)?;
            let result = crate::release_https::HttpsTransport::new()
                .and_then(|transport| transport.public_ipv4(&budget));
            drop(finished);
            watcher.join().map_err(refused)?;
            context.check()?;
            result.map_err(refused)
        })
    }
}

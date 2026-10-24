//! Closed native command vocabulary. No caller-controlled argv or shell.
use super::*;
use crate::host::process::{self, CommandOutput};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Proxy,
    Subscription,
    Firewall,
}
impl Unit {
    pub fn name(self) -> &'static str {
        match self {
            Self::Proxy => "sing-box.service",
            Self::Subscription => "sbxr-subscription.service",
            Self::Firewall => "sbxr-subscription-firewall.service",
        }
    }
    pub fn cgroup(self) -> &'static str {
        match self {
            Self::Proxy => "/system.slice/sing-box.service",
            Self::Subscription => runtime_handoff::SUBSCRIPTION_CGROUP,
            Self::Firewall => "/system.slice/sbxr-subscription-firewall.service",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Property {
    ActiveState,
    MainPid,
    ControlPid,
    ControlGroup,
    KillMode,
    FragmentPath,
    DropInPaths,
    LoadState,
    ExecStart,
    ExecStop,
    ExecCondition,
}
impl Property {
    pub fn name(self) -> &'static str {
        match self {
            Self::ActiveState => "ActiveState",
            Self::MainPid => "MainPID",
            Self::ControlPid => "ControlPID",
            Self::ControlGroup => "ControlGroup",
            Self::KillMode => "KillMode",
            Self::FragmentPath => "FragmentPath",
            Self::DropInPaths => "DropInPaths",
            Self::LoadState => "LoadState",
            Self::ExecStart => "ExecStart",
            Self::ExecStop => "ExecStop",
            Self::ExecCondition => "ExecCondition",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Property(Unit, Property),
    Firewall,
    ProxyProcesses,
    Listener443,
    Listener8443,
    Listener10000,
    Package,
    Hold,
    UnitOwner,
    User,
    Group,
    Architecture,
    Enabled,
}
impl Observation {
    pub fn command(self) -> (&'static str, Vec<String>) {
        let (program, args) = match self {
            Self::Property(u, p) => {
                return (
                    "/usr/bin/systemctl",
                    vec![
                        "show".into(),
                        format!("--property={}", p.name()),
                        "--value".into(),
                        u.name().into(),
                    ],
                );
            }
            Self::Firewall => ("/usr/sbin/iptables-save", vec!["-t", "filter"]),
            Self::ProxyProcesses => ("/usr/bin/pgrep", vec!["-x", "sing-box"]),
            Self::Listener10000 => ("/usr/bin/ss", vec!["-H", "-ltnp", "sport", "=", ":10000"]),
            Self::Listener443 => ("/usr/bin/ss", vec!["-H", "-ltnp", "sport", "=", ":443"]),
            Self::Listener8443 => ("/usr/bin/ss", vec!["-H", "-ltnp", "sport", "=", ":8443"]),
            Self::Package => (
                "/usr/bin/dpkg-query",
                vec![
                    "--show",
                    "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}",
                    "sing-box",
                ],
            ),
            Self::Hold => ("/usr/bin/apt-mark", vec!["showhold"]),
            Self::Architecture => ("/usr/bin/dpkg", vec!["--print-architecture"]),
            Self::Enabled => ("/usr/bin/systemctl", vec!["is-enabled", "sing-box.service"]),
            Self::User => ("/usr/bin/getent", vec!["passwd", "sing-box"]),
            Self::Group => ("/usr/bin/getent", vec!["group", "sing-box"]),
            Self::UnitOwner => (
                "/usr/bin/dpkg-query",
                vec!["--search", "/usr/lib/systemd/system/sing-box.service"],
            ),
        };
        (program, args.into_iter().map(str::to_owned).collect())
    }
}
/// Explicit fixture transport; production uses only NativeIo below. Both execute
/// this same closed vocabulary. The start channel is never passed to a command.
pub trait OwnerIo: PeerObservations + Sync {
    fn query(
        &self,
        observation: Observation,
        context: &StartContext,
    ) -> Result<CommandOutput, HostError>;
    fn service(
        &self,
        action: ServiceAction,
        owner: &Arc<HostLock>,
        fixture_channel: Option<&Path>,
        context: &StartContext,
    ) -> Result<(), HostError>;
    fn port_available(&self, port: u16, context: &StartContext) -> Result<bool, HostError>;
    fn process(&self, pid: u32) -> Result<runtime_handoff::ProcessIdentity, HostError>;
    fn historical(
        &self,
        _: HistoricalObservation,
        _: &StartContext,
    ) -> Result<CommandOutput, HostError> {
        Err(HostError::LiveUnavailable)
    }
    fn public_ipv4(&self, context: &StartContext) -> Result<std::net::Ipv4Addr, HostError>;
    fn validate_configuration(
        &self,
        owner: &Arc<HostLock>,
        expected: &str,
        context: &StartContext,
    ) -> Result<bool, HostError>;
}
pub struct NativeIo;
impl PeerObservations for NativeIo {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        runtime_handoff::LinuxPeers.current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        runtime_handoff::LinuxPeers.peer(s)
    }
}
impl OwnerIo for NativeIo {
    fn historical(
        &self,
        q: HistoricalObservation,
        c: &StartContext,
    ) -> Result<CommandOutput, HostError> {
        let (p, a) = q.command();
        native_command(p, &a, c)
    }

    fn query(
        &self,
        observation: Observation,
        ctx: &StartContext,
    ) -> Result<CommandOutput, HostError> {
        let (program, args) = observation.command();
        native_command(program, &args, ctx)
    }
    fn service(
        &self,
        action: ServiceAction,
        owner: &Arc<HostLock>,
        channel: Option<&Path>,
        ctx: &StartContext,
    ) -> Result<(), HostError> {
        if channel.is_some() || owner.root() != Path::new("/") {
            return Err(HostError::Unsafe);
        }
        owner.verify()?;
        let args = action
            .arguments()
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        let output = native_command("/usr/bin/systemctl", &args, ctx)?;
        owner.verify()?;
        if output.code() != 0 {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    fn validate_configuration(
        &self,
        owner: &Arc<HostLock>,
        expected: &str,
        ctx: &StartContext,
    ) -> Result<bool, HostError> {
        crate::host::linux::require_native_environment()?;
        if owner.root() != Path::new("/") {
            return Err(HostError::Unsafe);
        }
        owner.verify()?;
        let fs = ProtectedFs::native()?;
        let (bytes, _) = fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if sha256_hex(&bytes) != expected
            || crate::server_configuration::ServerConfiguration::decode_supported(&bytes).is_err()
        {
            return Err(HostError::Foreign);
        }
        let package = self.query(Observation::Package, ctx)?;
        let hold = self.query(Observation::Hold, ctx)?;
        if package.code() != 0
            || !crate::package_acquisition::exact_held_package(package.text()?)
            || hold.code() != 0
            || hold
                .text()?
                .lines()
                .filter(|line| *line == "sing-box")
                .count()
                != 1
        {
            return Err(HostError::Foreign);
        }
        let result = native_command(
            "/usr/bin/sing-box",
            &["-D", "/var/lib/sing-box", "-C", "/etc/sing-box", "check"].map(str::to_owned),
            ctx,
        )?;
        owner.verify()?;
        let (after, _) = fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if after != bytes {
            return Err(HostError::Foreign);
        }
        Ok(result.code() == 0)
    }
    fn port_available(&self, port: u16, ctx: &StartContext) -> Result<bool, HostError> {
        crate::host::linux::require_native_environment()?;
        ctx.check().map_err(refused)?;
        if !matches!(port, 443 | 8443) {
            return Err(HostError::Unsafe);
        }
        Ok(std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok())
    }
    fn process(&self, pid: u32) -> Result<runtime_handoff::ProcessIdentity, HostError> {
        runtime_handoff::linux_process(pid).map_err(refused)
    }
    fn public_ipv4(&self, ctx: &StartContext) -> Result<std::net::Ipv4Addr, HostError> {
        use crate::host::runtime::ServingEnvironment;
        crate::host::runtime::NativeServingEnvironment
            .public_ipv4(ctx)
            .map_err(refused)
    }
}
fn native_command(
    program: &str,
    args: &[String],
    ctx: &StartContext,
) -> Result<CommandOutput, HostError> {
    crate::host::linux::require_native_environment()?;
    ctx.check().map_err(refused)?;
    let before = program_proof(program)?;
    let output = crate::host::runtime::command::run(ctx, |cancel| {
        process::run_in(
            program,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            "/",
            ctx.deadline()
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(15)),
            process::OUTPUT_LIMIT,
            cancel,
        )
    })
    .map_err(refused)?;
    if program_proof(program)? != before {
        return Err(HostError::Unsafe);
    }
    Ok(output)
}

fn program_proof(program: &str) -> Result<Vec<crate::host::filesystem::Evidence>, HostError> {
    if program != "/usr/sbin/iptables-save" {
        return Ok(vec![crate::host::linux::verify_probe_executable(program)?]);
    }
    firewall_program(&ProtectedFs::native()?)
}
pub(super) fn firewall_program(
    fs: &ProtectedFs,
) -> Result<Vec<crate::host::filesystem::Evidence>, HostError> {
    use crate::host::filesystem::{Kind, Resource};
    if let Ok(Some((_, p))) = fs.raw(
        "usr/sbin/iptables-save",
        Mode::from_raw_mode(0o755),
        16 << 20,
    ) && p.gid == fs.gid
    {
        return Ok(vec![p]);
    }
    let mut proof = Vec::new();
    let first = fs
        .observe(Resource {
            path: "usr/sbin/iptables-save",
            kind: Kind::Link("/etc/alternatives/iptables-save"),
        })?
        .ok_or(HostError::Foreign)?;
    if first.gid != fs.gid {
        return Err(HostError::Foreign);
    }
    proof.push(first);
    for (link, binary, target) in [
        (
            "/usr/sbin/iptables-nft-save",
            "usr/sbin/iptables-nft-save",
            "xtables-nft-multi",
        ),
        (
            "/usr/sbin/iptables-legacy-save",
            "usr/sbin/iptables-legacy-save",
            "xtables-legacy-multi",
        ),
    ] {
        if let Ok(Some(p)) = fs.observe(Resource {
            path: "etc/alternatives/iptables-save",
            kind: Kind::Link(link),
        }) {
            if p.gid != fs.gid {
                return Err(HostError::Foreign);
            }
            proof.push(p);
            let p = fs
                .observe(Resource {
                    path: binary,
                    kind: Kind::Link(target),
                })?
                .ok_or(HostError::Foreign)?;
            if p.gid != fs.gid {
                return Err(HostError::Foreign);
            }
            proof.push(p);
            let (_, p) = fs
                .raw(
                    &format!("usr/sbin/{target}"),
                    Mode::from_raw_mode(0o755),
                    16 << 20,
                )?
                .ok_or(HostError::Foreign)?;
            if p.gid != fs.gid {
                return Err(HostError::Foreign);
            }
            proof.push(p);
            return Ok(proof);
        }
    }
    Err(HostError::Foreign)
}

impl<I: OwnerIo> PeerObservations for Arc<I> {
    fn current(&self) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        (**self).current()
    }
    fn peer(
        &self,
        s: &std::os::unix::net::UnixStream,
    ) -> Result<runtime_handoff::ProcessIdentity, runtime_handoff::Error> {
        (**self).peer(s)
    }
}
impl<I: OwnerIo + Send> OwnerIo for Arc<I> {
    fn query(&self, o: Observation, c: &StartContext) -> Result<CommandOutput, HostError> {
        (**self).query(o, c)
    }
    fn service(
        &self,
        a: ServiceAction,
        l: &Arc<HostLock>,
        s: Option<&Path>,
        c: &StartContext,
    ) -> Result<(), HostError> {
        (**self).service(a, l, s, c)
    }
    fn validate_configuration(
        &self,
        o: &Arc<HostLock>,
        e: &str,
        c: &StartContext,
    ) -> Result<bool, HostError> {
        (**self).validate_configuration(o, e, c)
    }
    fn public_ipv4(&self, c: &StartContext) -> Result<std::net::Ipv4Addr, HostError> {
        (**self).public_ipv4(c)
    }
    fn process(&self, p: u32) -> Result<runtime_handoff::ProcessIdentity, HostError> {
        (**self).process(p)
    }
    fn port_available(&self, p: u16, c: &StartContext) -> Result<bool, HostError> {
        (**self).port_available(p, c)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalObservation {
    Service(&'static str),
    Timer(&'static str),
    Snap,
    Changes,
    Boot,
    ProcessExists(u32),
}
impl HistoricalObservation {
    fn command(self) -> (&'static str, Vec<String>) {
        let (p, a) = match self {
            Self::Service(p) | Self::Timer(p) => {
                if ![
                    "ExecStart",
                    "FragmentPath",
                    "LoadState",
                    "DropInPaths",
                    "Unit",
                    "TimersCalendar",
                    "UnitFileState",
                    "ActiveState",
                ]
                .contains(&p)
                {
                    return ("/usr/bin/false", vec![]);
                };
                (
                    "/usr/bin/systemctl",
                    vec![
                        "show".into(),
                        format!("--property={p}"),
                        "--value".into(),
                        if matches!(self, Self::Service(_)) {
                            "snap.certbot.renew.service".into()
                        } else {
                            "snap.certbot.renew.timer".into()
                        },
                    ],
                )
            }
            Self::Snap => (
                "/usr/bin/snap",
                ["list", "certbot", "--unicode=always", "--color=never"]
                    .map(str::to_owned)
                    .to_vec(),
            ),
            Self::Changes => ("/usr/bin/snap", vec!["changes".into()]),
            Self::Boot => (
                "/usr/bin/cat",
                vec!["/proc/sys/kernel/random/boot_id".into()],
            ),
            Self::ProcessExists(pid) => {
                ("/usr/bin/test", vec!["-d".into(), format!("/proc/{pid}")])
            }
        };
        (p, a)
    }
}

use super::command::{Property as P, Unit as U};
use super::*;
impl<I: OwnerIo> OwnerRuntime<'_, I> {
    pub(super) fn package(&self, c: &StartContext) -> Result<(), HostError> {
        if !crate::package_acquisition::exact_held_package(&self.text(Observation::Package, c)?)
            || self
                .text(Observation::Hold, c)?
                .lines()
                .filter(|l| *l == "sing-box")
                .count()
                != 1
            || self.text(Observation::UnitOwner, c)?
                != "sing-box: /usr/lib/systemd/system/sing-box.service"
        {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(super) fn known_unit(&self, u: U, c: &StartContext) -> Result<(), HostError> {
        self.known_unit_context(u, c, false)
    }
    fn known_unit_context(&self, u: U, c: &StartContext, removal: bool) -> Result<(), HostError> {
        if u == U::Proxy {
            let (bytes, proof) = self
                .fs
                .raw(
                    "usr/lib/systemd/system/sing-box.service",
                    Mode::from_raw_mode(0o644),
                    8192,
                )?
                .ok_or(HostError::Foreign)?;
            if bytes != include_bytes!("testdata/sing-box.service") || proof.gid != self.fs.gid {
                return Err(HostError::Foreign);
            }
        }
        if u != U::Proxy {
            let (path, expected) = if u == U::Subscription {
                (
                    crate::host::subscription::UNIT,
                    runtime_handoff::SERVING_UNIT.as_bytes().to_vec(),
                )
            } else {
                (
                    crate::host::subscription::FIREWALL,
                    crate::host::historical::firewall_unit(&self.record()?)?,
                )
            };
            let (bytes, proof) = self
                .fs
                .raw(path, Mode::from_raw_mode(0o644), 8192)?
                .ok_or(HostError::Foreign)?;
            if (bytes != expected
                && !(removal
                    && u == U::Subscription
                    && crate::host::historical::has_authority(&self.record()?)
                    && crate::host::historical::known_serving_units().contains(&bytes)))
                || proof.gid != self.fs.gid
            {
                return Err(HostError::Foreign);
            }
        }
        let fragment = match u {
            U::Proxy => "/usr/lib/systemd/system/sing-box.service",
            U::Subscription => "/etc/systemd/system/sbxr-subscription.service",
            U::Firewall => "/etc/systemd/system/sbxr-subscription-firewall.service",
        };
        if self.property(u, P::LoadState, c)? != "loaded"
            || self.property(u, P::FragmentPath, c)? != fragment
        {
            return Err(HostError::Foreign);
        }
        let dropins = self.property(u, P::DropInPaths, c)?;
        let expected =
            if u == U::Proxy && self.fs.metadata(super::super::identity::STARTUP)?.is_some() {
                "/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf"
            } else {
                ""
            };
        if dropins != expected {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(super) fn proxy_running(
        &self,
        r: &OwnershipRecord,
        c: &StartContext,
    ) -> Result<bool, HostError> {
        self.package(c)?;
        self.known_unit(U::Proxy, c)?;
        if self.property(U::Proxy, P::ActiveState, c)? != "active" {
            return Ok(false);
        }
        let pid = self
            .property(U::Proxy, P::MainPid, c)?
            .parse::<u32>()
            .map_err(refused)?;
        if pid < 2
            || self.property(U::Proxy, P::ControlGroup, c)? != U::Proxy.cgroup()
            || self.text(Observation::ProxyProcesses, c)? != pid.to_string()
        {
            return Err(HostError::Foreign);
        }
        let processes = self
            .fs
            .cgroup_bytes(U::Proxy, false)?
            .ok_or(HostError::Foreign)?;
        if !std::str::from_utf8(&processes)
            .map_err(refused)?
            .split_whitespace()
            .any(|p| p == pid.to_string())
        {
            return Err(HostError::Foreign);
        }
        let listener = self.text(Observation::Listener443, c)?;
        if !listener
            .lines()
            .any(|line| listener_pid(line, 443, None, pid))
        {
            return Err(HostError::Foreign);
        }
        let (config, _) = self
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )?
            .ok_or(HostError::Foreign)?;
        if sha256_hex(&config) != r.configuration_sha256() {
            return Err(HostError::Foreign);
        }
        let user = self.text(Observation::User, c)?;
        let fields = user.split(':').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != "sing-box" {
            return Err(HostError::Foreign);
        }
        let uid = fields[2].parse::<u32>().map_err(refused)?;
        let gid = fields[3].parse::<u32>().map_err(refused)?;
        let group = self.text(Observation::Group, c)?;
        let members = group.split(':').collect::<Vec<_>>();
        if uid == 0
            || members.len() != 4
            || members[0] != "sing-box"
            || members[2] != gid.to_string()
            || !members[3].is_empty()
        {
            return Err(HostError::Foreign);
        }
        if !exact_exec(
            &self.property(U::Proxy, P::ExecStart, c)?,
            "/usr/bin/sing-box",
            "/usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run",
        ) {
            return Err(HostError::Foreign);
        }
        let process = self.io.process(pid)?;
        let (binary, _) = self
            .fs
            .raw("usr/bin/sing-box", Mode::from_raw_mode(0o755), 256 << 20)?
            .ok_or(HostError::Foreign)?;
        if process.uid != uid
            || process.cgroup != U::Proxy.cgroup()
            || process.executable_sha256 != sha256_hex(&binary)
            || self.io.process(pid)? != process
        {
            return Err(HostError::Foreign);
        }
        Ok(true)
    }
    pub(super) fn quiescence(&self, u: U, c: &StartContext) -> Result<bool, HostError> {
        self.fs
            .directory_entries("sys/fs/cgroup/system.slice", Mode::from_raw_mode(0o755))?
            .ok_or(HostError::Foreign)?;
        let active = self.property(u, P::ActiveState, c)?;
        let pid = self.property(u, P::MainPid, c)?;
        let group = self.property(u, P::ControlGroup, c)?;
        if active != "inactive" || pid != "0" || (!group.is_empty() && group != u.cgroup()) {
            return Ok(false);
        }
        if u == U::Proxy {
            if self.property(u, P::KillMode, c)? != "control-group" {
                return Ok(false);
            }
            let processes = self.io.query(Observation::ProxyProcesses, c)?;
            if processes.code() != 1 || !processes.text()?.is_empty() {
                return Ok(false);
            }
        }
        let query = if u == U::Proxy {
            Observation::Listener443
        } else {
            Observation::Listener8443
        };
        if !self.text(query, c)?.is_empty() {
            return Ok(false);
        }
        for _ in 0..2 {
            match self.fs.cgroup_bytes(u, true)? {
                Some(bytes) if population_empty(&bytes) => {}
                None if group.is_empty() => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }
    pub(super) fn serving_routes(&self, c: &StartContext) -> Result<(), HostError> {
        self.known_unit(U::Subscription, c)?;
        self.serving_exec(c)
    }
    pub(super) fn serving_routes_for_removal(&self, c: &StartContext) -> Result<(), HostError> {
        self.known_unit_context(U::Subscription, c, true)?;
        self.serving_exec(c)
    }
    fn serving_exec(&self, c: &StartContext) -> Result<(), HostError> {
        if !exact_exec(
            &self.property(U::Subscription, P::ExecStart, c)?,
            "/usr/local/bin/sbxr",
            "/usr/local/bin/sbxr --subscription-serving",
        ) {
            return Err(HostError::Foreign);
        }
        if self.property(U::Subscription, P::KillMode, c)? != "control-group" {
            return Err(HostError::Foreign);
        }
        Ok(())
    }
    pub(super) fn firewall_effective(
        &self,
        r: &OwnershipRecord,
        c: &StartContext,
    ) -> Result<(), HostError> {
        self.known_unit(U::Firewall, c)?;
        if self.property(U::Firewall, P::MainPid, c)? != "0"
            || self.property(U::Firewall, P::ControlPid, c)? != "0"
        {
            return Err(HostError::Foreign);
        }
        let unit = crate::host::historical::firewall_unit(r)?;
        for (p, key) in [(P::ExecStart, "ExecStart="), (P::ExecStop, "ExecStop=")] {
            let expected: Vec<_> = std::str::from_utf8(&unit)
                .map_err(refused)?
                .lines()
                .filter_map(|l| l.strip_prefix(key))
                .collect();
            let loaded = self.property(U::Firewall, p, c)?;
            if !historical::firewall_commands(&loaded, &expected) {
                return Err(HostError::Foreign);
            }
        }
        Ok(())
    }
}
pub(super) fn listener_pid(line: &str, port: u16, ip: Option<&str>, pid: u32) -> bool {
    let f: Vec<_> = line.split_whitespace().collect();
    if f.len() < 5 || !line.contains(&format!("pid={pid},")) {
        return false;
    }
    match ip {
        Some(ip) => f[3] == format!("{ip}:{port}"),
        None => [
            format!("*:{port}"),
            format!("[::]:{port}"),
            format!("0.0.0.0:{port}"),
        ]
        .contains(&f[3].to_owned()),
    }
}
pub(super) fn population_empty(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| {
        s.lines()
            .filter(|l| l.starts_with("populated "))
            .collect::<Vec<_>>()
            == ["populated 0"]
    })
}
pub(in crate::host) fn exact_exec(body: &str, path: &str, argv: &str) -> bool {
    let body = body.trim();
    if !body.starts_with('{')
        || !body.ends_with('}')
        || body.matches('{').count() != 1
        || body.matches('}').count() != 1
    {
        return body == argv && body.split_whitespace().next() == Some(path);
    }
    let mut fields = std::collections::BTreeMap::new();
    for part in body[1..body.len() - 1].trim().split(" ; ") {
        let Some((key, value)) = part.trim().split_once('=') else {
            return false;
        };
        if ![
            "path",
            "argv[]",
            "ignore_errors",
            "start_time",
            "stop_time",
            "pid",
            "code",
            "status",
        ]
        .contains(&key)
            || fields.insert(key, value).is_some()
        {
            return false;
        }
    }
    fields.get("path") == Some(&path)
        && fields.get("argv[]") == Some(&argv)
        && fields.get("ignore_errors") == Some(&"no")
}

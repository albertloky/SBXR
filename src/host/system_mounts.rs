//! Mount-scoped account ownership. Kernel metadata is not account data;
//! tmpfs/devtmpfs and unknown filesystem types remain in scope.
use super::*;
use std::time::Instant;

#[derive(Debug)]
struct Mount {
    id: u64,
    parent: u64,
    path: String,
    virtual_metadata: bool,
    filesystem: String,
    root: String,
}
fn mount_path(raw: &str) -> Result<String, HostError> {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escape: String = chars.by_ref().take(3).collect();
            out.push(match escape.as_str() {
                "040" => ' ',
                "011" => '\t',
                "012" => '\n',
                "134" => '\\',
                _ => return Err(HostError::Unsafe),
            });
        } else if c.is_control() {
            return Err(HostError::Unsafe);
        } else {
            out.push(c);
        }
    }
    if !out.starts_with('/')
        || (out != "/"
            && out
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == ".."))
    {
        return Err(HostError::Unsafe);
    }
    Ok(out)
}
fn mounts(bytes: &[u8]) -> Result<Vec<Mount>, HostError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HostError::Unsafe)?;
    if bytes.len() > process::OUTPUT_LIMIT || !text.ends_with('\n') {
        return Err(HostError::Unsafe);
    }
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        let f: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = f.iter().position(|s| *s == "-").ok_or(HostError::Unsafe)?;
        if separator < 6 || f.len() != separator + 4 {
            return Err(HostError::Unsafe);
        }
        let number = |s: &str| s.parse::<u64>().map_err(|_| HostError::Unsafe);
        let id = number(f[0])?;
        let parent = number(f[1])?;
        let dev: Vec<_> = f[2].split(':').collect();
        if id == 0 || !ids.insert(id) || dev.len() != 2 {
            return Err(HostError::Unsafe);
        }
        number(dev[0])?;
        number(dev[1])?;
        let root = mount_path(f[3])?;
        let path = mount_path(f[4])?;
        let virtual_metadata = matches!(
            f[separator + 1],
            "proc" | "sysfs" | "cgroup" | "cgroup2" | "devpts" | "binfmt_misc"
        );
        result.push(Mount {
            id,
            parent,
            path,
            virtual_metadata,
            filesystem: f[separator + 1].into(),
            root,
        });
    }
    // systemd overlays its binfmt automount with the kernel binfmt metadata
    // filesystem. Collapse only that exact two-layer relationship. All other
    // stacks still refuse: hidden data cannot be proved by a pathname scan.
    let binfmt = "/proc/sys/fs/binfmt_misc";
    let layers: Vec<_> = result.iter().filter(|m| m.path == binfmt).collect();
    if layers.len() == 2 {
        let lower = layers
            .iter()
            .find(|m| m.filesystem == "autofs")
            .ok_or(HostError::Unsafe)?;
        let upper = layers
            .iter()
            .find(|m| m.filesystem == "binfmt_misc")
            .ok_or(HostError::Unsafe)?;
        if lower.root != "/"
            || upper.root != "/"
            || upper.parent != lower.id
            || !result
                .iter()
                .any(|m| m.id == lower.parent && m.path == "/proc" && m.filesystem == "proc")
        {
            return Err(HostError::Unsafe);
        }
        let (lower_id, upper_id, parent_id) = (lower.id, upper.id, lower.parent);
        result.retain(|m| m.id != lower_id);
        result
            .iter_mut()
            .find(|m| m.id == upper_id)
            .ok_or(HostError::Unsafe)?
            .parent = parent_id;
        // A child of the hidden automount retains its old parent ID and is
        // rejected below; only visible children of binfmt remain traversable.
    }
    let mut paths = BTreeSet::new();
    if result.iter().any(|m| !paths.insert(m.path.clone())) {
        return Err(HostError::Unsafe);
    }
    if !result.iter().any(|m| m.path == "/" && !m.virtual_metadata) {
        return Err(HostError::Unsafe);
    }
    // A pathname below a covering mount may still describe an older hidden
    // child of another parent. Such records must not prune the visible tree.
    // Refuse ambiguous visibility instead of guessing from pathnames alone.
    for mount in &result {
        if mount.path == "/" {
            // Root may parent itself, or refer outside the process root, but
            // cannot be parented by one of its visible descendants.
            if mount.parent != mount.id && ids.contains(&mount.parent) {
                return Err(HostError::Unsafe);
            }
            continue;
        }
        let parent = result
            .iter()
            .filter(|m| m.path != mount.path && within(&mount.path, &m.path))
            .max_by_key(|m| m.path.len())
            .ok_or(HostError::Unsafe)?;
        if mount.parent != parent.id {
            return Err(HostError::Unsafe);
        }
    }
    Ok(result)
}
fn within(path: &str, parent: &str) -> bool {
    path == parent
        || parent == "/"
        || path
            .strip_prefix(parent)
            .is_some_and(|s| s.starts_with('/'))
}
fn literal(path: &str) -> String {
    path.chars()
        .flat_map(|c| {
            if "\\*?[]".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}
fn scan_args(root: &Path, mount: &Mount, all: &[Mount], uid: Option<u32>, gid: u32) -> Vec<String> {
    let local = |path: &str| {
        root.join(path.trim_start_matches('/'))
            .to_string_lossy()
            .into_owned()
    };
    let mut args = vec![local(&mount.path), "-xdev".into()];
    // The validated topology makes each immediate child a traversal barrier.
    // Deeper descendants are already behind that prune; listing them again
    // adds per-entry comparisons without changing coverage. Every data mount
    // is still scanned independently, including below virtual and bind mounts.
    let children: Vec<_> = all
        .iter()
        .filter(|m| m.path != mount.path && m.parent == mount.id)
        .collect();
    if !children.is_empty() {
        args.push("(".into());
        for (i, child) in children.iter().enumerate() {
            if i > 0 {
                args.push("-o".into());
            }
            args.extend(["-path".into(), literal(&local(&child.path))]);
        }
        args.extend([")".into(), "-prune".into(), "-o".into()]);
    }
    args.push("(".into());
    if let Some(uid) = uid {
        args.extend(["-uid".into(), uid.to_string(), "-o".into()]);
    }
    args.extend(["-gid".into(), gid.to_string(), ")".into()]);
    if uid.is_some() {
        for (path, subtree) in [
            ("/etc/sing-box/config.json", false),
            ("/var/lib/sing-box", true),
        ] {
            // A nested mount under state is independently owned data, not an
            // extension of the state-directory pathname exception.
            if within(path, &mount.path) {
                let pattern = literal(&local(path));
                args.extend(["!".into(), "-path".into(), pattern.clone()]);
                if subtree {
                    args.extend(["!".into(), "-path".into(), format!("{pattern}/*")]);
                }
            }
        }
    }
    args.extend(["-print".into(), "-quit".into()]);
    args
}
impl<T: Transport> SystemRunner<T> {
    fn scan_output(
        &self,
        program: &'static str,
        args: &[String],
        stop: &Cancellation,
        deadline: Instant,
    ) -> Result<CommandOutput, HostError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(HostError::Timeout)?;
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        let mut command = CommandSpec::fixed(
            program,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            false,
        );
        // Reading mount metadata remains an ordinary bounded query. Walking
        // every data mount shares the larger whole-scan budget below.
        command.timeout = Some(if program == "/usr/bin/cat" {
            remaining.min(Duration::from_secs(5))
        } else {
            remaining
        });
        let out = self.transport.run(&command, stop)?;
        if stop.cancelled() {
            return Err(HostError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(HostError::Timeout);
        }
        if out.code() != 0 {
            return Err(HostError::Unsafe);
        }
        Ok(out)
    }
    pub(super) fn account_files(
        &self,
        uid: Option<u32>,
        gid: u32,
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        // A complete filesystem walk is not a five-second metadata query:
        // the captured q205 root alone required 5.47s, and all mounts 6.03s.
        // Keep one finite, cancellable budget, never a fresh one per mount.
        self.account_files_until(uid, gid, stop, Instant::now() + Duration::from_secs(30))
    }
    fn account_files_until(
        &self,
        uid: Option<u32>,
        gid: u32,
        stop: &Cancellation,
        deadline: Instant,
    ) -> Result<(), HostError> {
        let path = vec![self.path("/proc/self/mountinfo")];
        let before = self.scan_output("/usr/bin/cat", &path, stop, deadline)?;
        let all = mounts(before.bytes())?;
        for mount in all.iter().filter(|m| !m.virtual_metadata) {
            let args = scan_args(&self.root, mount, &all, uid, gid);
            let out = self.scan_output("/usr/bin/find", &args, stop, deadline)?;
            if !out.bytes().is_empty() {
                return Err(HostError::Foreign);
            }
        }
        let after = self.scan_output("/usr/bin/cat", &path, stop, deadline)?;
        if before.bytes() != after.bytes() {
            return Err(HostError::Unsafe);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "system_mounts_tests.rs"]
mod tests;

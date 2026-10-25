//! Retained Certbot route admission; no hooks are executed or changed here.
use super::*;
impl HistoricalHttps {
    pub(in crate::host) fn renewal_hooks_safe(&self) -> Result<(), HostError> {
        for directory in ["pre", "deploy", "post"] {
            let parent = format!("etc/letsencrypt/renewal-hooks/{directory}");
            for name in self.fs.historical_directory_entries(&parent)? {
                let path = format!("{parent}/{name}");
                let (body, mode) = self
                    .fs
                    .historical_readable(&path, true)?
                    .ok_or(HostError::Foreign)?;
                if mode.as_raw_mode() & 0o111 != 0
                    && body
                        .windows(b"/usr/local/bin/sbxr".len())
                        .any(|w| w == b"/usr/local/bin/sbxr")
                    && path != renewal::DEPLOY
                    && path != renewal::POST
                {
                    return Err(HostError::Foreign);
                }
            }
        }
        let mut paths = vec!["etc/letsencrypt/cli.ini".to_owned()];
        for name in self
            .fs
            .historical_directory_entries("etc/letsencrypt/renewal")?
        {
            if !name.ends_with(".conf") {
                return Err(HostError::Foreign);
            }
            paths.push(format!("etc/letsencrypt/renewal/{name}"));
        }
        for path in paths {
            if let Some((body, _)) = self.fs.historical_readable(&path, true)? {
                let body = std::str::from_utf8(&body).map_err(|_| HostError::Foreign)?;
                for line in body.lines() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim().replace('-', "_");
                        let value = value.trim();
                        if key == "no_directory_hooks"
                            && !["false", "0", "no", "off"]
                                .contains(&value.to_ascii_lowercase().as_str())
                            || ["pre_hook", "post_hook", "deploy_hook", "renew_hook"]
                                .contains(&key.as_str())
                                && value.contains("/usr/local/bin/sbxr")
                        {
                            return Err(HostError::Foreign);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

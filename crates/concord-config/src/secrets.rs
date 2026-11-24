use std::collections::BTreeMap;
use std::env::VarError;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use concord_pve::Secret;
use zeroize::Zeroizing;

use crate::{error_line, Config, ConfigError};

/// Overrides the configuration's `secrets_file`.
pub const SECRETS_FILE_ENV: &str = "CONCORD_SECRETS_FILE";

/// Far more than any estate needs; stops a wrong path reading something huge.
const MAX_FILE: u64 = 1 << 20;

/// Token secrets by host name. Printing it shows names only, since [`Secret`]
/// redacts itself.
#[derive(Clone, Debug)]
pub struct Secrets(BTreeMap<String, Secret>);

/// The variable that overrides one host's secret.
pub fn token_env_var(host: &str) -> String {
    let name: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CONCORD_TOKEN_{name}")
}

pub(crate) fn missing(host: &str) -> ConfigError {
    ConfigError::MissingSecret {
        host: host.to_string(),
        env: token_env_var(host),
    }
}

impl Secrets {
    /// Gathers a secret for every configured host, the environment winning over
    /// the file. Secrets for hosts that are not configured are not kept.
    pub fn load(cfg: &Config) -> Result<Secrets, ConfigError> {
        Self::load_with(cfg, &|k| std::env::var(k))
    }

    // The environment is a parameter because changing the real one in a test
    // races with every other test in the process.
    pub(crate) fn load_with(
        cfg: &Config,
        env: &dyn Fn(&str) -> Result<String, VarError>,
    ) -> Result<Secrets, ConfigError> {
        let path = lookup(env, SECRETS_FILE_ENV)?
            .map(PathBuf::from)
            .or_else(|| cfg.secrets_file.clone());
        let mut file = match path {
            Some(p) => read_file(&p)?,
            None => BTreeMap::new(),
        };
        let mut out = BTreeMap::new();
        for h in &cfg.hosts {
            let from_env = lookup(env, &token_env_var(&h.name))?.map(Secret::new);
            let secret = from_env
                .or_else(|| file.remove(&h.name))
                .ok_or_else(|| missing(&h.name))?;
            out.insert(h.name.clone(), secret);
        }
        Ok(Secrets(out))
    }

    pub fn get(&self, host: &str) -> Option<&Secret> {
        self.0.get(host)
    }
}

fn lookup(
    env: &dyn Fn(&str) -> Result<String, VarError>,
    key: &str,
) -> Result<Option<String>, ConfigError> {
    match env(key) {
        Ok(v) if v.is_empty() => Err(ConfigError::Invalid {
            field: key.to_string(),
            reason: "set but empty".into(),
        }),
        Ok(v) => Ok(Some(v)),
        Err(VarError::NotPresent) => Ok(None),
        // VarError's own text quotes the value, which may be a secret.
        Err(VarError::NotUnicode(_)) => Err(ConfigError::Invalid {
            field: key.to_string(),
            reason: "not valid UTF-8".into(),
        }),
    }
}

fn read_file(path: &Path) -> Result<BTreeMap<String, Secret>, ConfigError> {
    let read_err = |source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    };
    let refuse = |reason: &str| ConfigError::SecretsFile {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };

    // Opened once, and everything after is asked of the descriptor: checking
    // the path and then opening it would let the file be swapped in between.
    let file = open(path).map_err(read_err)?;
    let meta = file.metadata().map_err(read_err)?;
    if !meta.is_file() {
        return Err(refuse("not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // The owner can rewrite the file or reopen its mode, so it has to be
        // someone who could act as this process anyway.
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !trusted_owner(meta.uid(), euid) {
            return Err(refuse("owned by neither root nor the user running Concord"));
        }
        let mode = meta.permissions().mode() & 0o7777;
        // All three bits, not just read: whoever can write it picks the token.
        if mode & 0o077 != 0 {
            return Err(refuse(&format!(
                "mode {mode:04o} gives access to group or others; use chmod 600"
            )));
        }
    }
    if meta.len() > MAX_FILE {
        return Err(refuse("too large to be a secrets file"));
    }

    // Reserved up front so the buffer is not reallocated as it fills, leaving
    // copies that are never wiped.
    let capacity = usize::try_from(meta.len()).unwrap_or(0).saturating_add(1);
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    file.take(MAX_FILE)
        .read_to_string(&mut text)
        .map_err(read_err)?;

    // The parser's own text quotes the offending line, so only where it is.
    let raw: BTreeMap<String, String> = toml::from_str(&text).map_err(|e| {
        refuse(&format!(
            "line {}: expected `host = \"secret\"` entries",
            error_line(&text, &e)
        ))
    })?;
    Ok(raw.into_iter().map(|(k, v)| (k, Secret::new(v))).collect())
}

#[cfg(unix)]
pub(crate) fn trusted_owner(owner: u32, euid: u32) -> bool {
    owner == euid || owner == 0
}

fn open(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Opening a FIFO would otherwise block before it can be refused.
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    opts.open(path)
}

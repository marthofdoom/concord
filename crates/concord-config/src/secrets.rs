use std::collections::BTreeMap;
use std::env::VarError;
use std::path::{Path, PathBuf};

use concord_pve::Secret;

use crate::{error_line, read_private, Config, ConfigError};

/// Overrides the configuration's `secrets_file`.
pub const SECRETS_FILE_ENV: &str = "CONCORD_SECRETS_FILE";

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
    let text = read_private(path)?;
    let refuse = |reason: &str| ConfigError::SecretsFile {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };
    // The parser's own text quotes the offending line, so only where it is.
    let raw: BTreeMap<String, String> = toml::from_str(&text).map_err(|e| {
        refuse(&format!(
            "line {}: expected `host = \"secret\"` entries",
            error_line(&text, &e)
        ))
    })?;
    Ok(raw.into_iter().map(|(k, v)| (k, Secret::new(v))).collect())
}

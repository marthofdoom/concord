//! Concord's configuration, and the PVE token secrets it needs to act on it.
//!
//! The two are separate files so that the configuration can be shown, copied
//! and serialised freely: [`Config`] has no field a secret could be in. Secrets
//! are only ever held in [`concord_pve::Secret`], and no error from this crate
//! carries a value
//! from either file, or a key that does not look like a field name.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod budget;
mod config;
mod private;
mod secrets;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use concord_pve::{ApiToken, HttpPveClient, PveApi, PveError};

pub use budget::Budget;
pub use config::{Config, HostConfig};
pub use private::{lock_beside, read_private, unsafe_for_root, write_private, DirLock};
pub use secrets::{token_env_var, Secrets, SECRETS_FILE_ENV};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The file is not TOML. Located by line only: a TOML error's own text
    /// quotes the source.
    #[error("{what}: syntax error on line {line}")]
    Syntax { what: &'static str, line: usize },

    #[error("{field}: {reason}")]
    Invalid { field: String, reason: String },

    #[error("credential file {}: {reason}", path.display())]
    SecretsFile { path: PathBuf, reason: String },

    #[error("no token secret for host {host:?}: add it to the secrets file or set {env}")]
    MissingSecret { host: String, env: String },

    #[error("host {host:?}: {source}")]
    Client { host: String, source: PveError },
}

/// Clients by host name.
pub type Clients = Vec<(String, Arc<dyn PveApi>)>;

impl Config {
    /// One pinned, authenticated client per host, in configuration order.
    pub fn build_clients(
        &self,
        secrets: &Secrets,
        timeout: Duration,
    ) -> Result<Clients, ConfigError> {
        self.hosts
            .iter()
            .map(|h| {
                let client_err = |source| ConfigError::Client {
                    host: h.name.clone(),
                    source,
                };
                let secret = secrets
                    .get(&h.name)
                    .ok_or_else(|| secrets::missing(&h.name))?;
                let (user, id) = ApiToken::parse_full_id(&h.token_id).map_err(client_err)?;
                let token = ApiToken::new(user, id, secret.clone());
                let client = HttpPveClient::new(h.api_url.clone(), token, h.fingerprint, timeout)
                    .map_err(client_err)?;
                Ok((h.name.clone(), Arc::new(client) as Arc<dyn PveApi>))
            })
            .collect()
    }
}

/// 1-based line of a TOML error, the only part of it safe to repeat.
fn error_line(text: &str, e: &toml::de::Error) -> usize {
    let at = e.span().map_or(0, |s| s.start);
    1 + text.bytes().take(at).filter(|b| *b == b'\n').count()
}

#[cfg(test)]
mod tests;

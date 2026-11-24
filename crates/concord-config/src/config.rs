use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use concord_core::FENCE_DEADLINE;
use concord_pve::{ApiToken, Fingerprint, PveError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use url::Url;

use crate::secrets::token_env_var;
use crate::{error_line, Budget, ConfigError};

/// Loopback, so that reaching the API from elsewhere is a decision.
const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 8010);
const DEFAULT_STATE_DIR: &str = "/var/lib/concord";
const DEFAULT_POLL_SECS: u64 = 10;
/// Far past any sensible setting; keeps arithmetic on the durations, such as
/// `restore_delay`, away from overflow.
const MAX_SECS: u64 = 3600;

/// A validated configuration. Not `Deserialize`: [`Config::parse`] and
/// [`Config::load`] are the only ways in from text, so nothing can skip the
/// checks.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Config {
    pub listen: SocketAddr,
    pub poll_interval_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence_deadline_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_file: Option<PathBuf>,
    /// What Concord itself keeps, such as its generated certificate.
    pub state_dir: PathBuf,
    /// API users and tokens. [`Config::users_path`] applies the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users_file: Option<PathBuf>,
    /// Whether root on any host may sign in here, as an admin of all of them.
    pub pve_root_login: bool,
    /// Both or neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    pub hosts: Vec<HostConfig>,
    pub budget: Budget,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct HostConfig {
    pub name: String,
    /// Bare https origin, e.g. `https://pve1:8006`.
    #[serde(serialize_with = "as_string")]
    pub api_url: Url,
    #[serde(serialize_with = "as_string")]
    pub fingerprint: Fingerprint,
    /// `USER@REALM!TOKENID`, without the secret.
    pub token_id: String,
}

fn as_string<S: Serializer>(v: &impl std::fmt::Display, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(v)
}

// Hosts and budget stay untyped here and are decoded one at a time, so an error
// in one can say which.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Option<SocketAddr>,
    poll_interval_secs: Option<u64>,
    fence_deadline_secs: Option<u64>,
    secrets_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    users_file: Option<PathBuf>,
    pve_root_login: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    #[serde(default)]
    hosts: Vec<toml::Value>,
    budget: Option<toml::Value>,
}

// Optional so that a missing field is reported by its own path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    name: Option<String>,
    api_url: Option<String>,
    fingerprint: Option<String>,
    token_id: Option<String>,
}

impl Config {
    /// Reads and validates `path`. Relative paths are taken relative to the
    /// configuration file, so they do not depend on the working directory a
    /// service happens to start in.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg = Config::parse(&text)?;
        if let Some(dir) = path.parent() {
            cfg.state_dir = dir.join(&cfg.state_dir);
            for file in [
                &mut cfg.secrets_file,
                &mut cfg.users_file,
                &mut cfg.tls_cert,
                &mut cfg.tls_key,
            ]
            .into_iter()
            .flatten()
            {
                *file = dir.join(&*file);
            }
        }
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let table: toml::Table = toml::from_str(text).map_err(|e| ConfigError::Syntax {
            what: "configuration",
            line: error_line(text, &e),
        })?;
        let raw: RawConfig = decode("", toml::Value::Table(table))?;

        if raw.hosts.is_empty() {
            return Err(invalid("hosts", "at least one [[hosts]] entry is required"));
        }
        let mut hosts: Vec<HostConfig> = Vec::with_capacity(raw.hosts.len());
        // Distinct names can share an override variable, and then one host
        // would be sent another's token.
        let mut vars: HashMap<String, usize> = HashMap::new();
        for (i, value) in raw.hosts.into_iter().enumerate() {
            let at = format!("hosts[{i}]");
            let host = check_host(&at, decode(&at, value)?)?;
            if let Some(j) = vars.insert(token_env_var(&host.name), i) {
                let reason = if hosts[j].name == host.name {
                    format!("same name as hosts[{j}]")
                } else {
                    format!(
                        "shares the variable {} with hosts[{j}]; rename one of them",
                        token_env_var(&host.name)
                    )
                };
                return Err(invalid(&format!("{at}.name"), reason));
            }
            hosts.push(host);
        }

        let budget: Budget = match raw.budget {
            Some(v) => decode("budget", v)?,
            None => Budget::default(),
        };
        budget
            .check()
            .map_err(|(field, reason)| invalid(&format!("budget.{field}"), reason))?;

        let poll_interval_secs = raw.poll_interval_secs.unwrap_or(DEFAULT_POLL_SECS);
        check_secs("poll_interval_secs", poll_interval_secs)?;
        if let Some(secs) = raw.fence_deadline_secs {
            check_secs("fence_deadline_secs", secs)?;
        }
        match (&raw.tls_cert, &raw.tls_key) {
            (Some(_), None) => return Err(invalid("tls_key", "required with tls_cert")),
            (None, Some(_)) => return Err(invalid("tls_cert", "required with tls_key")),
            _ => {}
        }
        Ok(Config {
            listen: raw.listen.unwrap_or(DEFAULT_LISTEN),
            poll_interval_secs,
            fence_deadline_secs: raw.fence_deadline_secs,
            secrets_file: raw.secrets_file,
            state_dir: raw.state_dir.unwrap_or_else(|| DEFAULT_STATE_DIR.into()),
            users_file: raw.users_file,
            pve_root_login: raw.pve_root_login.unwrap_or(true),
            tls_cert: raw.tls_cert,
            tls_key: raw.tls_key,
            hosts,
            budget,
        })
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs)
    }

    pub fn users_path(&self) -> PathBuf {
        self.users_file
            .clone()
            .unwrap_or_else(|| self.state_dir.join("users.toml"))
    }

    /// The override, or [`FENCE_DEADLINE`].
    pub fn fence_deadline(&self) -> Duration {
        self.fence_deadline_secs
            .map_or(FENCE_DEADLINE, Duration::from_secs)
    }
}

fn invalid(field: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field: field.to_string(),
        reason: reason.into(),
    }
}

/// Decodes an already parsed value, so the error has a key to name and no
/// source text to quote.
fn decode<T: DeserializeOwned>(at: &str, value: toml::Value) -> Result<T, ConfigError> {
    value.try_into().map_err(|e: toml::de::Error| {
        // Its Display ends in "in `key`" when the fault is below `value`.
        let full = e.to_string();
        let key = full
            .trim_end()
            .rsplit_once("\nin `")
            .and_then(|(_, k)| k.strip_suffix('`'));
        let field = match (at, key) {
            ("", None) => "configuration".to_string(),
            ("", Some(k)) => k.to_string(),
            (at, None) => at.to_string(),
            (at, Some(k)) => format!("{at}.{k}"),
        };
        // Serde quotes a string of the wrong type, and a credential pasted into
        // the wrong field should not reach a log.
        let msg = e.message();
        let reason = if let Some(rest) = msg.strip_prefix("unknown field `") {
            // From the right, because the key itself may contain anything.
            match rest.rsplit_once("`, expected ") {
                Some((k, want)) if plausible_field(k) => {
                    format!("unknown field `{k}`, expected {want}")
                }
                _ => "unknown field (name withheld, it may be a misplaced credential)".to_string(),
            }
        } else if msg.starts_with("invalid type") || msg.starts_with("invalid value") {
            match msg.rsplit_once(", expected ") {
                Some((_, want)) => format!("wrong type, expected {want}"),
                None => "wrong type".to_string(),
            }
        } else {
            msg.to_string()
        };
        invalid(&field, reason)
    })
}

/// Whether a key looks like a mistyped field name, and so can be repeated. A
/// token secret, with its digits, never does.
fn plausible_field(key: &str) -> bool {
    key.len() <= 24 && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn check_secs(field: &str, secs: u64) -> Result<(), ConfigError> {
    if (1..=MAX_SECS).contains(&secs) {
        Ok(())
    } else {
        Err(invalid(field, format!("must be 1 to {MAX_SECS}")))
    }
}

fn check_host(at: &str, raw: RawHost) -> Result<HostConfig, ConfigError> {
    let field = |f: &str| format!("{at}.{f}");
    let need = |v: Option<String>, f: &str| v.ok_or_else(|| invalid(&field(f), "missing"));
    let from_pve = |f: &str, e: PveError| match e {
        PveError::InvalidRequest(why) => invalid(&field(f), why),
        other => invalid(&field(f), other.to_string()),
    };

    let name = need(raw.name, "name")?;
    let starts_ok = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    if !starts_ok
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(invalid(
            &field("name"),
            "must start with a letter or digit and contain only letters, digits, '.', '-' and '_'",
        ));
    }

    let text = need(raw.api_url, "api_url")?;
    let api_url: Url = text
        .parse()
        .map_err(|e: url::ParseError| invalid(&field("api_url"), e.to_string()))?;
    if api_url.scheme() != "https" {
        return Err(invalid(&field("api_url"), "must be https"));
    }
    // HttpPveClient refuses these too; checked here so the error names the
    // field, and so userinfo never becomes part of a Config that is printed.
    if api_url.path() != "/"
        || api_url.query().is_some()
        || api_url.fragment().is_some()
        || !api_url.username().is_empty()
        || api_url.password().is_some()
    {
        return Err(invalid(
            &field("api_url"),
            "must be a bare origin such as https://pve1:8006",
        ));
    }

    let fingerprint = need(raw.fingerprint, "fingerprint")?
        .parse()
        .map_err(|e| from_pve("fingerprint", e))?;
    let token_id = need(raw.token_id, "token_id")?;
    ApiToken::parse_full_id(&token_id).map_err(|e| from_pve("token_id", e))?;

    Ok(HostConfig {
        name,
        api_url,
        fingerprint,
        token_id,
    })
}

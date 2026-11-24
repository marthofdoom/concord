//! Config file and credential loading.
//!
//! The two secrets (the PVE token and the login passphrase) are read only
//! from files systemd hands over with `LoadCredential=`, never from argv or
//! the environment, where `ps` and `/proc/<pid>/environ` would show them.
//! The source files stay root:root 0600, so the service user cannot rewrite
//! its own credential. No error built here quotes a file's
//! contents.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use concord_pve::{ApiToken, Fingerprint, Secret};
use serde::Deserialize;

use crate::estate::Node;

/// The only identity nestview accepts: build.sh's pool-scoped token
/// (`PUSER` and `TOKEN_NAME` in testbed/nested/lib.sh). A broader token in the
/// file is refused rather than used.
pub const TOKEN_USER: &str = "concord@pve";
pub const TOKEN_ID: &str = "nest";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_bind")]
    bind: String,
    pve_url: String,
    fingerprint: String,
    /// The PVE node the estate runs on. Required, like every site value: a
    /// built-in default would be somebody else's host.
    node: String,
    /// `Host` values the UI is reached by (`192.0.2.x:8099`). Required:
    /// there is no default that would be right.
    allowed_hosts: Vec<String>,
    #[serde(default = "default_audit_log")]
    audit_log: PathBuf,
    allowed_clients: Vec<String>,
    #[serde(default = "default_refresh_secs")]
    refresh_secs: u64,
    #[serde(default = "default_task_timeout_secs")]
    task_timeout_secs: u64,
    #[serde(default = "default_session_ttl_secs")]
    session_ttl_secs: u64,
}

fn default_bind() -> String {
    "0.0.0.0:8099".into()
}
fn default_audit_log() -> PathBuf {
    "/var/lib/nestview/audit.jsonl".into()
}
fn default_refresh_secs() -> u64 {
    3
}
fn default_task_timeout_secs() -> u64 {
    300
}
fn default_session_ttl_secs() -> u64 {
    8 * 3600
}

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub pve_url: url::Url,
    pub fingerprint: Fingerprint,
    pub node: Node,
    /// Lower-cased. Every request's `Host` must be one of these, and every
    /// POST's `Origin` must be `http://` plus one of these.
    pub allowed_hosts: Vec<String>,
    pub audit_log: PathBuf,
    /// Second line of defence behind the container's nftables: requests from
    /// any other peer address get a 403.
    pub allowed_clients: Vec<IpAddr>,
    pub refresh: Duration,
    pub task_timeout: Duration,
    pub session_ttl: Duration,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Config> {
        // The example's placeholders that would otherwise pass as host names.
        for p in ["PVE_HOST", "CT_IP"] {
            if text.contains(p) {
                anyhow::bail!("config still contains the placeholder {p}");
            }
        }
        let raw: RawConfig =
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("invalid config: {e}"))?;
        let bind: SocketAddr = raw
            .bind
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid bind address {:?}", raw.bind))?;
        let pve_url =
            url::Url::parse(&raw.pve_url).map_err(|e| anyhow::anyhow!("invalid pve_url: {e}"))?;
        let fingerprint: Fingerprint = raw
            .fingerprint
            .parse()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let node = Node::new(&raw.node).map_err(|e| anyhow::anyhow!(e))?;
        let mut allowed_clients = Vec::new();
        for c in &raw.allowed_clients {
            // Canonical form, as the peer address is compared: an entry
            // written `::ffff:192.0.2.10` must still match.
            allowed_clients.push(
                c.parse::<IpAddr>()
                    .map_err(|_| anyhow::anyhow!("invalid allowed_clients entry {c:?}"))?
                    .to_canonical(),
            );
        }
        let mut allowed_hosts = Vec::new();
        for h in &raw.allowed_hosts {
            let ok = !h.is_empty()
                && h.len() <= 255
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b));
            if !ok {
                anyhow::bail!("invalid allowed_hosts entry {h:?} (expected host:port)");
            }
            allowed_hosts.push(h.to_ascii_lowercase());
        }
        if allowed_hosts.is_empty() {
            anyhow::bail!("allowed_hosts must name at least one host:port");
        }
        if allowed_clients.is_empty() {
            anyhow::bail!("allowed_clients must name at least one address");
        }
        if !(1..=60).contains(&raw.refresh_secs) {
            anyhow::bail!("refresh_secs must be 1-60");
        }
        if raw.task_timeout_secs == 0 {
            anyhow::bail!("task_timeout_secs must be positive");
        }
        if !(60..=7 * 86_400).contains(&raw.session_ttl_secs) {
            anyhow::bail!("session_ttl_secs must be 60-604800");
        }
        Ok(Config {
            bind,
            pve_url,
            fingerprint,
            node,
            allowed_hosts,
            audit_log: raw.audit_log,
            allowed_clients,
            refresh: Duration::from_secs(raw.refresh_secs),
            task_timeout: Duration::from_secs(raw.task_timeout_secs),
            session_ttl: Duration::from_secs(raw.session_ttl_secs),
        })
    }
}

/// Where systemd's `LoadCredential=` put the credentials: the directory in
/// `$CREDENTIALS_DIRECTORY`. Only the directory's path comes from the
/// environment, never a secret.
pub fn credentials_dir() -> anyhow::Result<PathBuf> {
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        anyhow::anyhow!(
            "CREDENTIALS_DIRECTORY is not set; run under systemd with LoadCredential=token:... \
             and LoadCredential=passphrase:... (see nestview.service)"
        )
    })?;
    Ok(PathBuf::from(dir))
}

/// Mode bits a credential must not have: any write bit, and any bit for
/// others. Group read is allowed, and has to be: for a unit with
/// `User=`, systemd writes each credential 0400 and grants the service user
/// read through an ACL entry. On an ACL-capable filesystem (tmpfs, which is
/// where `/run/credentials` lives) the group bits of `st_mode` then show the
/// ACL mask, so the file stats as 0440 even though the owning group has no
/// access (`group::---`). The mask is only as wide as the entries it covers,
/// a read grant, so it never shows a write bit.
const CREDENTIAL_FORBIDDEN: u32 = 0o227;

/// Reads a credential systemd placed in `$CREDENTIALS_DIRECTORY`. Refused if
/// it is writable by anyone or readable by others; see [`CREDENTIAL_FORBIDDEN`]
/// for why group read is not refused. The source files under `/etc/nestview`
/// stay root:root 0600, and only this service can open the directory.
pub fn read_secret_file(path: &Path, what: &str) -> anyhow::Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("cannot stat {what} file {}: {e}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & CREDENTIAL_FORBIDDEN != 0 {
        anyhow::bail!(
            "{what} file {} has mode {:o}; a credential must not be writable, nor readable \
             by others (systemd's LoadCredential= delivers it 0400, plus a read ACL)",
            path.display(),
            mode & 0o777
        );
    }
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {what} file {}: {e}", path.display()))
}

/// Reads the token file build.sh writes: one line,
/// `concord@pve!nest=<uuid secret>` (jq's `"\(.["full-tokenid"])=\(.value)"`).
pub fn load_token(path: &Path) -> anyhow::Result<ApiToken> {
    let mut text = read_secret_file(path, "token")?;
    let r = parse_token(&text);
    zeroize::Zeroize::zeroize(&mut text);
    r.map_err(|why| anyhow::anyhow!("token file {}: {why}", path.display()))
}

/// Errors name what was wrong, never the text that was there.
pub fn parse_token(text: &str) -> Result<ApiToken, &'static str> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains(['\n', '\r']) {
        return Err("expected exactly one line");
    }
    let (full_id, secret) = line
        .rsplit_once('=')
        .ok_or("expected USER@REALM!TOKENID=SECRET")?;
    let (user, token_id) = full_id
        .split_once('!')
        .ok_or("expected USER@REALM!TOKENID=SECRET")?;
    if user != TOKEN_USER || token_id != TOKEN_ID {
        return Err("only the pool-scoped token concord@pve!nest is accepted");
    }
    if secret.is_empty() {
        return Err("secret is empty");
    }
    Ok(ApiToken::new(user, token_id, Secret::new(secret)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    #[test]
    fn parses_build_sh_token_line() {
        let t = parse_token(&format!("concord@pve!nest={SECRET}\n")).unwrap();
        assert_eq!(t.user, "concord@pve");
        assert_eq!(t.token_id, "nest");
    }

    #[test]
    fn refuses_other_tokens() {
        assert!(parse_token(&format!("root@pam!other={SECRET}")).is_err());
        assert!(parse_token(&format!("concord@pve!other={SECRET}")).is_err());
        assert!(parse_token(&format!("concord@pve!nest={SECRET}\nextra")).is_err());
    }

    #[test]
    fn token_secret_never_in_debug_or_errors() {
        let t = parse_token(&format!("concord@pve!nest={SECRET}")).unwrap();
        assert!(!format!("{t:?}").contains(SECRET));

        // Errors from a wrong token, or a malformed one, do not echo the line.
        for bad in [
            format!("root@pam!x={SECRET}"),
            format!("concord@pve!nest{SECRET}"),
            format!("{SECRET}\n{SECRET}"),
        ] {
            let e = parse_token(&bad).unwrap_err();
            assert!(!e.contains(SECRET), "{e}");
        }

        // Through the file loader too, including the permission refusal.
        let dir = std::env::temp_dir().join(format!("nestview-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        use std::os::unix::fs::PermissionsExt;
        let chmod =
            |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
        std::fs::write(&path, format!("root@pam!x={SECRET}\n")).unwrap();
        chmod(0o400);
        let e = load_token(&path).unwrap_err();
        assert!(!format!("{e:?} {e}").contains(SECRET));

        chmod(0o600);
        std::fs::write(&path, format!("concord@pve!nest={SECRET}\n")).unwrap();
        chmod(0o644);
        let e = load_token(&path).unwrap_err();
        assert!(e.to_string().contains("has mode 644"), "{e}");
        assert!(!format!("{e:?} {e}").contains(SECRET));

        chmod(0o400);
        let t = load_token(&path).unwrap();
        assert!(!format!("{t:?}").contains(SECRET));
        chmod(0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What systemd hands a `User=` service stats as 0440 on
    /// tmpfs (0400 plus a read ACL, which shows as the group bits), so that
    /// must load. A write bit or an "other" bit must not.
    #[test]
    fn credential_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nestview-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, format!("concord@pve!nest={SECRET}\n")).unwrap();
        let chmod =
            |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
        for ok in [0o400, 0o440] {
            chmod(ok);
            assert!(load_token(&path).is_ok(), "{ok:o} must be accepted");
        }
        for bad in [0o600, 0o640, 0o420, 0o404, 0o401, 0o444, 0o402] {
            chmod(bad);
            let e = load_token(&path).unwrap_err();
            assert!(
                e.to_string().contains(&format!("has mode {bad:o}")),
                "{bad:o}: {e}"
            );
            assert!(!format!("{e:?} {e}").contains(SECRET));
        }
        chmod(0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_defaults_and_validation() {
        let c = Config::parse(
            r#"{"pve_url":"https://192.0.2.10:8006",
                "fingerprint":"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F",
                "node":"pve1","allowed_clients":["192.0.2.10"],
                "allowed_hosts":["192.0.2.77:8099"]}"#,
        )
        .unwrap();
        assert_eq!(c.allowed_hosts, vec!["192.0.2.77:8099".to_string()]);
        assert_eq!(c.session_ttl, Duration::from_secs(8 * 3600));
        assert_eq!(c.bind.to_string(), "0.0.0.0:8099");
        assert_eq!(c.node.as_str(), "pve1");
        assert_eq!(
            c.allowed_clients,
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()]
        );
        // No secret field exists, so a config can never carry one; nor a
        // token file path (the credential comes from systemd).
        for extra in [
            r#""token":"x""#,
            r#""passphrase":"x""#,
            r#""token_file":"/t""#,
        ] {
            let e = Config::parse(&format!(
                r#"{{"pve_url":"https://h:8006","allowed_hosts":["h:8099"],{extra},
                "node":"pve1","allowed_clients":["192.0.2.10"],
                "fingerprint":"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F"}}"#
            ))
            .unwrap_err();
            assert!(e.to_string().contains("unknown field"), "{e}");
        }
        // allowed_hosts is required and validated.
        let base = r#""pve_url":"https://h:8006","node":"pve1","allowed_clients":["192.0.2.10"],"fingerprint":"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F""#;
        assert!(Config::parse(&format!("{{{base}}}")).is_err());
        assert!(Config::parse(&format!(r#"{{{base},"allowed_hosts":[]}}"#)).is_err());
        assert!(Config::parse(&format!(r#"{{{base},"allowed_hosts":["a/b"]}}"#)).is_err());
    }

    #[test]
    fn allowed_clients_are_canonicalized() {
        let c = Config::parse(
            r#"{"pve_url":"https://192.0.2.10:8006","allowed_hosts":["h:8099"],"node":"pve1",
                "fingerprint":"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F",
                "allowed_clients":["::ffff:192.0.2.10"]}"#,
        )
        .unwrap();
        assert_eq!(
            c.allowed_clients,
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn site_values_have_no_defaults() {
        let full = serde_json::json!({
            "pve_url": "https://h:8006", "node": "pve1", "allowed_hosts": ["h:8099"],
            "allowed_clients": ["192.0.2.10"],
            "fingerprint": "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F",
        });
        assert!(Config::parse(&full.to_string()).is_ok());
        for key in [
            "pve_url",
            "node",
            "allowed_hosts",
            "allowed_clients",
            "fingerprint",
        ] {
            let mut v = full.clone();
            v.as_object_mut().unwrap().remove(key);
            let e = Config::parse(&v.to_string()).unwrap_err();
            assert!(e.to_string().contains(key), "{key}: {e}");
        }
    }

    /// Unedited, the example must not start; with its five placeholders filled
    /// in, it must.
    #[test]
    fn shipped_example_config_needs_editing() {
        let example = include_str!("../deploy/config.example.json");
        let fill = [
            ("PVE_HOST", "192.0.2.10"),
            ("PVE_CERT_SHA256", "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F"),
            ("NODE_NAME", "pve1"),
            ("CT_IP", "192.0.2.77"),
            ("OPERATOR_IP", "192.0.2.10"),
        ];
        assert!(Config::parse(example).is_err());
        // Nor with any single placeholder left in. (PVE_HOST and CT_IP are
        // legal host names, so they are checked as placeholders.)
        for skip in 0..fill.len() {
            let mut t = example.to_string();
            for (i, (k, v)) in fill.iter().enumerate() {
                if i != skip {
                    t = t.replace(k, v);
                }
            }
            assert!(Config::parse(&t).is_err(), "{} left in", fill[skip].0);
        }
        let mut t = example.to_string();
        for (k, v) in fill {
            t = t.replace(k, v);
        }
        let c = Config::parse(&t).unwrap();
        assert_eq!(c.bind.to_string(), "0.0.0.0:8099");
        assert_eq!(c.allowed_hosts, vec!["192.0.2.77:8099".to_string()]);
    }
}

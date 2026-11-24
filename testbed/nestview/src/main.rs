//! nestview: a dashboard and manual test controls for the nested PVE test
//! estate (VMs 9001-9003). Runs in an LXC on the estate's host and serves only
//! the configured client addresses.
//!
//! Usage: `nestview [--config PATH]` (default `/etc/nestview/config.json`).
//! The API token and the login passphrase are read from the credentials
//! systemd passes with `LoadCredential=` (`$CREDENTIALS_DIRECTORY/token` and
//! `.../passphrase`); neither is ever taken from the command line or the
//! environment.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod audit;
mod auth;
mod config;
mod control;
mod estate;
mod status;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use concord_pve::{HttpPveClient, PveApi};
use tokio::sync::{watch, Mutex, Notify};

use crate::config::{credentials_dir, load_token, Config};

const DEFAULT_CONFIG: &str = "/etc/nestview/config.json";

/// Per-request timeout towards PVE. Task waits poll, so this bounds one poll,
/// not a whole task.
const PVE_TIMEOUT: Duration = Duration::from_secs(20);

fn config_path() -> anyhow::Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from(DEFAULT_CONFIG);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config needs a path"))?
                    .into();
            }
            "-h" | "--help" => {
                println!("usage: nestview [--config PATH]   (default {DEFAULT_CONFIG})");
                std::process::exit(0);
            }
            // Not echoed: if someone pastes a secret here, it stays out of the journal.
            _ => anyhow::bail!("unknown argument (usage: nestview [--config PATH])"),
        }
    }
    Ok(path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::load(&config_path()?)?;
    let creds = credentials_dir()?;
    let token = load_token(&creds.join("token"))?;
    let passphrase = auth::load_passphrase(&creds.join("passphrase"))?;
    let client = HttpPveClient::new(cfg.pve_url.clone(), token, cfg.fingerprint, PVE_TIMEOUT)?;
    let api: Arc<dyn PveApi> = Arc::new(client);
    let audit = audit::AuditLog::open(&cfg.audit_log)
        .map_err(|e| anyhow::anyhow!("cannot open audit log {}: {e}", cfg.audit_log.display()))?;

    let (tx, rx) = watch::channel(None);
    let kick = Arc::new(Notify::new());
    let mut poller = tokio::spawn(status::run_poller(
        api.clone(),
        cfg.node.clone(),
        cfg.refresh,
        tx,
        kick.clone(),
    ));

    let state = Arc::new(web::AppState {
        api,
        node: cfg.node.clone(),
        allowed_clients: cfg.allowed_clients.clone(),
        allowed_hosts: cfg.allowed_hosts.clone(),
        task_timeout: cfg.task_timeout,
        audit,
        snapshot: rx,
        kick,
        busy: Arc::new(Mutex::new(())),
        passphrase,
        sessions: auth::Sessions::new(cfg.session_ttl),
    });
    let app = web::router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(
        bind = %cfg.bind,
        pve = %cfg.pve_url,
        node = cfg.node.as_str(),
        "nestview listening"
    );
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    // The poller loops forever; if it ever ends (a panic), /api/status would
    // serve a stale snapshot indefinitely. Exit instead, non-zero, so systemd
    // restarts the service.
    tokio::select! {
        r = server => r?,
        r = &mut poller => {
            let why = match r {
                Ok(()) => "returned".to_string(),
                Err(e) => e.to_string(),
            };
            tracing::error!(why, "status poller ended; exiting so systemd restarts nestview");
            anyhow::bail!("status poller ended: {why}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use concord_pve::{HttpPveClient, Method, PveApi};

    use crate::config::parse_token;

    const SECRET: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    /// The real client, failing for real (nothing listens on port 1): neither
    /// the error nor the client's Debug output carries the secret.
    #[tokio::test]
    async fn token_absent_from_client_debug_and_errors() {
        let token = parse_token(&format!("concord@pve!nest={SECRET}\n")).unwrap();
        let fp = "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F"
            .parse()
            .unwrap();
        let client = HttpPveClient::new(
            url::Url::parse("https://127.0.0.1:1").unwrap(),
            token,
            fp,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!format!("{client:?}").contains(SECRET));
        let e = client
            .request(Method::Get, "/version", &[])
            .await
            .unwrap_err();
        assert!(!format!("{e} {e:?}").contains(SECRET));
        let report = crate::control::run(
            &client,
            &crate::estate::Node::new("pve1").unwrap(),
            crate::estate::Vmid::new(9001).unwrap(),
            &crate::control::Action::Kill,
            false,
            Duration::from_secs(2),
            &crate::control::NoRecord,
        )
        .await;
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(SECRET) && !format!("{report:?}").contains(SECRET));
    }
}

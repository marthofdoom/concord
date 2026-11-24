//! Concord's orchestrator. Runs in a container on a PVE host and serves the
//! API and web UI that stand in for a cluster's.
//!
//! Scaffold: the listener, health surface and read-only inventory are real;
//! the other subsystems land per `docs/ARCHITECTURE.md`.

use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use concord_config::{Config, Secrets};
use concord_inventory::{InventoryConfig, Poller};
use concord_server::cli::{self, Cli};
use concord_server::serve::{self, Limits};
use concord_server::{guard_host, router, tls, AppState, Auth, AuthConfig};

/// Per PVE request. A dark host must fail well inside the host deadline, so
/// one powered-off machine delays the others' fresh data by seconds only.
const PVE_TIMEOUT: Duration = Duration::from_secs(5);

/// PVE holds a refusal back for three seconds, so this is not `PVE_TIMEOUT`.
const PVE_LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on one host's whole poll.
const HOST_DEADLINE: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        // Under a supervisor the output goes to syslog, where colour codes are
        // noise.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let path = &cli.config;
    let config =
        Config::load(path).with_context(|| format!("loading config {}", path.display()))?;
    if let Some(command) = &cli.command {
        return cli::manage(command, &config.users_path(), &mut std::io::stdout());
    }
    let secrets = Secrets::load(&config).context("loading token secrets")?;
    let hosts = config.build_clients(&secrets, PVE_TIMEOUT)?;
    drop(secrets);

    let addr = config.listen;
    let tls = tls::setup(&config)?;
    match &tls {
        Some(t) => tracing::info!(fingerprint = %t.fingerprint, "serving HTTPS"),
        None => tracing::info!("serving plain HTTP, on loopback only"),
    }
    let mut auth = AuthConfig::new(config.users_path(), tls.is_some());
    auth.pve = config.build_root_logins(PVE_LOGIN_TIMEOUT)?;
    if !auth.pve.is_empty() {
        tracing::info!("root on any configured host may sign in (pve_root_login)");
    }
    let auth = Auth::new(auth)?;

    let (poller, inventory) = Poller::new(
        hosts,
        InventoryConfig {
            interval: config.poll_interval(),
            host_deadline: HOST_DEADLINE,
            ..InventoryConfig::default()
        },
    );
    let poller = tokio::spawn(poller.run());
    let app = guard_host(router(AppState { inventory }, auth), addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = concord_core::VERSION, "concord listening");

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    tokio::select! {
        served = serve::serve(listener, app, tls.as_ref(), Limits::default(), stop_rx) => {
            served.map_err(Into::into)
        }
        // The poller never returns, so this is a panic. Serving on would
        // present a frozen estate as a live one.
        ended = poller => {
            ended.context("inventory poller died")?;
            anyhow::bail!("inventory poller stopped")
        }
    }
}

/// Ctrl-C interactively; SIGTERM is how systemd and container runtimes stop it.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot listen for SIGTERM");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    tracing::info!("shutting down");
}

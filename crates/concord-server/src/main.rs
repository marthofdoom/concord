//! Concord's orchestrator. Runs in a container on a PVE host and serves the
//! API and web UI that stand in for a cluster's.
//!
//! Scaffold: the listener, health surface and read-only inventory are real;
//! the other subsystems land per `docs/ARCHITECTURE.md`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use concord_config::{Config, Secrets};
use concord_inventory::{InventoryConfig, Poller};
use concord_server::{guard_host, router, AppState};

const DEFAULT_CONFIG: &str = "/etc/concord/concord.toml";

/// Per PVE request. A dark host must fail well inside the host deadline, so
/// one powered-off machine delays the others' fresh data by seconds only.
const PVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long open connections get to finish after a stop signal.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// Upper bound on one host's whole poll.
const HOST_DEADLINE: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let path = std::env::var_os("CONCORD_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_CONFIG.into());
    let config =
        Config::load(&path).with_context(|| format!("loading config {}", path.display()))?;
    let secrets = Secrets::load(&config).context("loading token secrets")?;
    let hosts = config.build_clients(&secrets, PVE_TIMEOUT)?;
    drop(secrets);

    let addr = config.listen;
    if !addr.ip().is_loopback() {
        // Allowed, because a reverse proxy in another container needs it, but
        // the API has no authentication yet and the estate is a map of every
        // guest.
        tracing::warn!(%addr, "listening beyond loopback with no API authentication");
    }

    let (poller, inventory) = Poller::new(
        hosts,
        InventoryConfig {
            interval: config.poll_interval(),
            host_deadline: HOST_DEADLINE,
            ..InventoryConfig::default()
        },
    );
    let poller = tokio::spawn(poller.run());
    let app = guard_host(router(AppState { inventory }), addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = concord_core::VERSION, "concord listening");

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    let mut graceful = stop_rx.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = graceful.wait_for(|stop| *stop).await;
    });
    // Graceful shutdown waits for open connections, and a client that stops
    // mid-request never finishes; so the drain is bounded.
    let mut drain = stop_rx;
    let drain_limit = async move {
        let _ = drain.wait_for(|stop| *stop).await;
        tokio::time::sleep(SHUTDOWN_DRAIN).await;
    };
    tokio::select! {
        served = server => served.map_err(Into::into),
        _ = drain_limit => {
            tracing::warn!("connections still open after {SHUTDOWN_DRAIN:?}; exiting anyway");
            Ok(())
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

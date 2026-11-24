//! Concord's orchestrator. Runs in a container on a PVE host and serves the
//! API and web UI that stand in for a cluster's.
//!
//! Scaffold: the listener and health surface are real; the subsystems behind
//! them land per `docs/ARCHITECTURE.md`.

use std::net::SocketAddr;

use axum::{routing::get, Json, Router};
use serde_json::json;

/// Default listen port. Deliberately *not* 8006 — Concord sits beside the PVE
/// web UI on the same host rather than displacing it.
const DEFAULT_PORT: u16 = 8010;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port = std::env::var("CONCORD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, version = concord_core::VERSION, "concord listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Liveness only. It answers while the process is up; it makes no claim about
/// whether the estate is healthy — that is `/api/v1/estate`, once it exists.
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "version": concord_core::VERSION }))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

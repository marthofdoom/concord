//! The host agent. Lives on the PVE node itself, outside the container, and
//! exists to solve the bootstrap problem: Concord cannot restart the container
//! Concord is running in.
//!
//! Scope is deliberately tiny — watch, and start what should be running.
//! Everything else belongs in the orchestrator.
//!
//! Scaffold: the loop shape is here; the PVE calls land per
//! `docs/ARCHITECTURE.md`.

use std::time::Duration;

/// How often the agent checks that Concord's own container is up.
const WATCH_INTERVAL: Duration = Duration::from_secs(30);

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    tracing::info!(
        version = concord_core::VERSION,
        interval_secs = WATCH_INTERVAL.as_secs(),
        "concord-agent starting"
    );

    // TODO(watchdog): poll the configured VMID via `pct status` / `qm status`
    // and start it when it is stopped, with backoff so a guest that is failing
    // to boot is not restarted in a tight loop.
    Ok(())
}

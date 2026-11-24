//! Concord's orchestrator: the HTTP API over the estate inventory.
//!
//! Split from the binary so tests drive the real router in-process.

mod host_guard;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use concord_core::GuestKind;
use concord_inventory::{Conflict, EstateSnapshot, Guest, HostSummary, InventoryHandle};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub use host_guard::guard_host;

/// Everything a handler may read. Handlers see the inventory snapshot, never a
/// PVE client.
#[derive(Clone)]
pub struct AppState {
    pub inventory: InventoryHandle,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        .route("/api/v1/estate", get(estate))
        .route("/api/v1/hosts", get(hosts))
        .route("/api/v1/guests", get(guests))
        .route("/api/v1/guests/{host}/{vmid}", get(guest))
        .with_state(state)
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// 503 until the first cycle finishes: an empty estate would be a claim, not
/// an absence of data. The error is boxed to keep `Result` small.
fn current(state: &AppState) -> Result<std::sync::Arc<EstateSnapshot>, Box<Response>> {
    state.inventory.current().ok_or_else(|| {
        Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inventory has not completed its first cycle",
        ))
    })
}

/// Liveness only. It answers while the process is up; it makes no claim about
/// whether the estate is healthy — that is `/api/v1/estate`.
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "version": concord_core::VERSION }))
}

async fn estate(State(s): State<AppState>) -> Response {
    match current(&s) {
        Ok(snap) => Json(&*snap).into_response(),
        Err(r) => *r,
    }
}

#[derive(Serialize)]
struct HostsBody {
    cycle: u64,
    taken_at: u64,
    hosts: Vec<HostSummary>,
    conflicts: Vec<Conflict>,
}

async fn hosts(State(s): State<AppState>) -> Response {
    match current(&s) {
        Ok(snap) => Json(HostsBody {
            cycle: snap.cycle,
            taken_at: snap.taken_at,
            hosts: snap.hosts.iter().map(|h| h.summary()).collect(),
            conflicts: snap.conflicts.clone(),
        })
        .into_response(),
        Err(r) => *r,
    }
}

#[derive(Deserialize)]
struct GuestQuery {
    host: Option<String>,
    kind: Option<String>,
    status: Option<String>,
}

/// A guest with the host it lives on, as the list shows it.
#[derive(Serialize)]
struct GuestRow {
    host: String,
    #[serde(flatten)]
    guest: Guest,
}

#[derive(Serialize)]
struct GuestsBody {
    cycle: u64,
    taken_at: u64,
    guests: Vec<GuestRow>,
}

async fn guests(State(s): State<AppState>, Query(q): Query<GuestQuery>) -> Response {
    let snap = match current(&s) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let kind = match q.kind.as_deref() {
        None => None,
        Some("qemu") => Some(GuestKind::Qemu),
        Some("lxc") => Some(GuestKind::Lxc),
        Some(_) => return error(StatusCode::BAD_REQUEST, "kind must be `qemu` or `lxc`"),
    };
    // An unknown host is an error, not an empty list: a typo must not look
    // like a host with no guests.
    if let Some(n) = &q.host {
        if !snap.hosts.iter().any(|h| h.name == *n) {
            return error(StatusCode::NOT_FOUND, "no such host");
        }
    }
    let rows = snap
        .hosts
        .iter()
        .filter(|h| q.host.as_ref().is_none_or(|n| *n == h.name))
        .flat_map(|h| h.guests.iter().map(move |g| (h, g)))
        .filter(|(_, g)| kind.is_none_or(|k| k == g.kind))
        .filter(|(_, g)| q.status.as_ref().is_none_or(|st| *st == g.status))
        .map(|(h, g)| {
            // The list is for scanning; config is fetched per guest.
            let mut guest = g.clone();
            guest.config = None;
            guest.config_omitted.clear();
            GuestRow {
                host: h.name.clone(),
                guest,
            }
        })
        .collect();
    Json(GuestsBody {
        cycle: snap.cycle,
        taken_at: snap.taken_at,
        guests: rows,
    })
    .into_response()
}

async fn guest(State(s): State<AppState>, Path((host, vmid)): Path<(String, u32)>) -> Response {
    let snap = match current(&s) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let found = snap
        .hosts
        .iter()
        .find(|h| h.name == host)
        .and_then(|h| h.guests.iter().find(|g| g.vmid == vmid));
    match found {
        Some(g) => Json(GuestRow {
            host,
            guest: g.clone(),
        })
        .into_response(),
        None => error(StatusCode::NOT_FOUND, "no such guest"),
    }
}

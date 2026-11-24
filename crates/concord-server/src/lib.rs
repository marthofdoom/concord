//! Concord's orchestrator: the HTTP API over the estate inventory.
//!
//! Split from the binary so tests drive the real router in-process.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod auth;
pub mod cli;
mod host_guard;
pub mod serve;
pub mod tls;
mod ui;
pub mod users;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use concord_core::GuestKind;
use concord_inventory::{Conflict, EstateSnapshot, Guest, HostSummary, InventoryHandle};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub use auth::{Auth, AuthConfig, Identity, Source};
pub use host_guard::guard_host;

/// Everything a handler may read. Handlers see the inventory snapshot, never a
/// PVE client.
#[derive(Clone)]
pub struct AppState {
    pub inventory: InventoryHandle,
}

/// Far past any request there is.
const MAX_BODY: usize = 64 * 1024;
/// From the end of the headers to the start of the response, the body included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; \
    form-action 'self'; frame-ancestors 'none'";

pub fn router(state: AppState, auth: Arc<Auth>) -> Router {
    router_with(state, auth, Router::new())
}

/// [`router`] with further API routes, which land behind the same gate.
///
/// The gate is a layer over the whole API rather than something each handler
/// asks for, and what is public is the short list merged outside it. `/api` has
/// a catch-all inside, so a path that does not exist is refused like any other.
pub fn router_with(state: AppState, auth: Arc<Auth>, extra: Router) -> Router {
    let gated = api_routes(state)
        .merge(extra)
        .route(
            auth::SESSION_PATH,
            post(auth::login).get(auth::whoami).delete(auth::logout),
        )
        .route("/api", any(no_route))
        .route("/api/{*rest}", any(no_route))
        .layer(Extension(auth.clone()))
        .layer(middleware::from_fn_with_state(auth, auth::require));
    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(ui::routes())
        .merge(gated)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn(time_limit));
    secure_headers(app)
}

fn api_routes(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/version", get(version))
        .route("/api/v1/estate", get(estate))
        .route("/api/v1/hosts", get(hosts))
        .route("/api/v1/guests", get(guests))
        .route("/api/v1/guests/{host}/{vmid}", get(guest))
        .with_state(state)
}

async fn no_route() -> Response {
    error(StatusCode::NOT_FOUND, "no such endpoint")
}

async fn time_limit(req: Request, next: Next) -> Response {
    tokio::time::timeout(REQUEST_TIMEOUT, next.run(req))
        .await
        .unwrap_or_else(|_| error(StatusCode::REQUEST_TIMEOUT, "request took too long"))
}

/// The headers every response carries. Applied outermost, so that refusals made
/// by other layers have them too.
pub(crate) fn secure_headers(app: Router) -> Router {
    app.layer(middleware::from_fn(|req: Request, next: Next| async {
        let path = req.uri().path();
        let api = path == "/api" || path.starts_with("/api/");
        let mut resp = next.run(req).await;
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        if api {
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        resp
    }))
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// With a word for programs to tell one 503 from another by.
fn coded(status: StatusCode, code: &'static str, msg: &'static str) -> Response {
    (status, Json(json!({ "error": msg, "code": code }))).into_response()
}

/// 503 until the first cycle finishes: an empty estate would be a claim, not
/// an absence of data. The error is boxed to keep `Result` small.
fn current(state: &AppState) -> Result<std::sync::Arc<EstateSnapshot>, Box<Response>> {
    state.inventory.current().ok_or_else(|| {
        Box::new(coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "starting",
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

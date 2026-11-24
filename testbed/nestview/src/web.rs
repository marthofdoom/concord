//! HTTP surface: login, the embedded UI, the cached status, and one control
//! route.
//!
//! There is no generic proxy. The only route that reaches PVE on request is
//! `POST /api/vm/{vmid}/{action}`, and it builds its calls from a [`Vmid`]
//! and a fixed [`Action`].
//!
//! Every request passes [`guard`] first: peer address, `Host`, and for a POST
//! `Origin` and `Sec-Fetch-Site`, then the session. Only the login page and
//! its stylesheet are served without a session.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use concord_pve::PveApi;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{watch, Mutex, Notify};
use zeroize::Zeroize;

use crate::audit::{now_rfc3339, request_id, AuditLog, Row};
use crate::auth::{self, Login, Passphrase, Sessions};
use crate::control::{self, Action, ActionResult, Call, Recorder};
use crate::estate::{Node, Vmid};
use crate::status::Snapshot;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const LOGIN_HTML: &str = include_str!("../assets/login.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// The login page posts a plain form, so it alone allows a same-origin form
/// action. It has no script at all.
const LOGIN_CSP: &str = "default-src 'none'; style-src 'self'; base-uri 'none'; \
                         form-action 'self'; frame-ancestors 'none'";

/// Not `no-referrer`. A form submission is a navigation, not a
/// CORS request, and for those the Fetch standard applies the document's
/// referrer policy to the `Origin` header too: under `no-referrer` the login
/// form's POST carries `Origin: null`, which [`check`] refuses, so a browser
/// could never log in. `same-origin` keeps the real Origin (and the Referer)
/// on requests to this dashboard and still sends nothing to any other origin.
pub const REFERRER_POLICY: &str = "same-origin";

pub struct AppState {
    pub api: Arc<dyn PveApi>,
    pub node: Node,
    pub allowed_clients: Vec<IpAddr>,
    /// Lower-cased `host:port` values; see [`crate::config::Config`].
    pub allowed_hosts: Vec<String>,
    pub task_timeout: Duration,
    pub audit: AuditLog,
    pub snapshot: watch::Receiver<Option<Arc<Snapshot>>>,
    pub kick: Arc<Notify>,
    /// One control at a time: a double click must not start a second stop
    /// while the first is still waiting on its task. Owned guards, so the
    /// spawned control holds it until it ends, whatever the client does.
    pub busy: Arc<Mutex<()>>,
    pub passphrase: Passphrase,
    pub sessions: Sessions,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/status", get(status))
        .route("/api/vm/{vmid}/{action}", post(control_route))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Served without a session: the login page and the stylesheet it links.
/// Neither carries any estate data.
fn is_public(method: &Method, path: &str) -> bool {
    path == "/login" || (method == Method::GET && path == "/app.css")
}

fn is_control(method: &Method, path: &str) -> bool {
    method == Method::POST && path.starts_with("/api/vm/")
}

/// Every check that does not need the request body, in order. Refusals of a
/// control POST are audited like the handler's own refusals.
async fn guard(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = peer.ip().to_canonical();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let refusal = check(&st, ip, &method, &path, req.headers(), req.uri());
    let mut resp = match refusal {
        None => next.run(req).await,
        Some((code, why)) => {
            tracing::warn!(%ip, method = %method, path = ?path, why, "refused request");
            if is_control(&method, &path) {
                audit_guard_refusal(&st, ip, &path, why);
            }
            if code == StatusCode::UNAUTHORIZED && method == Method::GET && path == "/" {
                // A browser opening the dashboard without a session goes to
                // the login page instead of seeing a bare 401.
                (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response()
            } else {
                (code, Json(json!({"result": "refused", "error": why}))).into_response()
            }
        }
    };
    let h = resp.headers_mut();
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
    }
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn check(
    st: &AppState,
    ip: IpAddr,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Option<(StatusCode, &'static str)> {
    // Behind the nftables rule that does the same.
    if !st.allowed_clients.contains(&ip) {
        return Some((StatusCode::FORBIDDEN, "client address not allowed"));
    }
    // DNS rebinding: a hostile page that rebinds its own name to
    // this address is same-origin with itself, but it cannot change the Host
    // its browser sends.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| uri.authority().map(|a| a.as_str().to_string()));
    let host_ok = host.is_some_and(|h| st.allowed_hosts.contains(&h.to_ascii_lowercase()));
    if !host_ok {
        return Some((StatusCode::FORBIDDEN, "Host is not one of allowed_hosts"));
    }
    if method != Method::GET && method != Method::HEAD {
        // Browsers send Origin on every POST, same-origin ones included.
        let origin_ok = headers
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
            .is_some_and(|o| {
                let o = o.to_ascii_lowercase();
                st.allowed_hosts
                    .iter()
                    .any(|a| o.strip_prefix("http://") == Some(a.as_str()))
            });
        if !origin_ok {
            return Some((
                StatusCode::FORBIDDEN,
                "Origin is missing or not this dashboard",
            ));
        }
        if let Some(site) = headers.get("sec-fetch-site") {
            if site.as_bytes() != b"same-origin" {
                return Some((StatusCode::FORBIDDEN, "Sec-Fetch-Site is not same-origin"));
            }
        }
    }
    if is_public(method, path) {
        return None;
    }
    let session_ok = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .filter_map(auth::session_from_cookie)
        .any(|id| st.sessions.valid(id));
    if !session_ok {
        return Some((StatusCode::UNAUTHORIZED, "not logged in"));
    }
    None
}

fn audit_guard_refusal(st: &AppState, ip: IpAddr, path: &str, why: &str) {
    let mut segs = path.trim_start_matches("/api/vm/").splitn(2, '/');
    let vmid: String = segs.next().unwrap_or("").chars().take(32).collect();
    let action: String = segs.next().unwrap_or("").chars().take(32).collect();
    let row = Row {
        ts: now_rfc3339(),
        req: request_id(),
        client_ip: ip,
        action,
        vmid,
        dry_run: None,
        result: "refused",
        upids: vec![],
        outcome: None,
        error: Some(why.to_string()),
        detail: None,
    };
    if let Err(e) = st.audit.write_unsynced(&row) {
        tracing::error!("audit log write failed: {e}");
    }
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

fn login_response(code: StatusCode, msg: &'static str) -> Response {
    // `msg` is one of the fixed strings below, never request text.
    let html = LOGIN_HTML.replace("<!--MSG-->", msg);
    (
        code,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, LOGIN_CSP),
        ],
        html,
    )
        .into_response()
}

async fn login_page() -> Response {
    login_response(StatusCode::OK, "")
}

/// No Debug: it holds the passphrase.
#[derive(Deserialize)]
pub struct LoginForm {
    passphrase: String,
}

async fn login(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Response {
    let ip = peer.ip().to_canonical();
    // The rejection text is not shown or logged: it is built from the body.
    let Ok(Form(mut f)) = form else {
        return login_response(
            StatusCode::BAD_REQUEST,
            r#"<p class="err">Malformed login form.</p>"#,
        );
    };
    let r = st.sessions.login(&st.passphrase, &f.passphrase);
    f.passphrase.zeroize();
    match r {
        Ok(Login::Ok(id)) => {
            tracing::info!(%ip, "login");
            let cookie = auth::set_cookie(&id, st.sessions.ttl());
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, "/".to_string()),
                    (header::SET_COOKIE, cookie),
                ],
            )
                .into_response()
        }
        Ok(Login::Wrong) => {
            tracing::warn!(%ip, "login failed: wrong passphrase");
            login_response(
                StatusCode::UNAUTHORIZED,
                r#"<p class="err">Wrong passphrase.</p>"#,
            )
        }
        Ok(Login::Limited) => {
            tracing::warn!(%ip, "login refused: too many failed logins");
            login_response(
                StatusCode::TOO_MANY_REQUESTS,
                r#"<p class="err">Too many failed logins. Wait a minute and try again.</p>"#,
            )
        }
        Err(e) => {
            tracing::error!("login: {e}");
            login_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"<p class="err">Could not create a session; see the journal.</p>"#,
            )
        }
    }
}

async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    for id in headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .filter_map(auth::session_from_cookie)
    {
        st.sessions.logout(id);
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, auth::clear_cookie())],
    )
        .into_response()
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn status(State(st): State<Arc<AppState>>) -> Response {
    let snap = st.snapshot.borrow().clone();
    match snap {
        Some(s) => Json(s.as_ref()).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "first status poll not finished yet"})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    /// Must equal the VMID in the path: the confirm step's typed answer.
    pub confirm_vmid: u32,
    /// Required, not defaulted: the client states which it means.
    pub dry_run: bool,
    #[serde(default)]
    pub snapname: Option<String>,
}

/// Writes the `started` and `task` rows of one control as it runs.
struct AuditRec<'a> {
    st: &'a AppState,
    req: &'a str,
    client_ip: IpAddr,
    action: &'static str,
    vmid: Vmid,
    detail: Option<Value>,
}

impl AuditRec<'_> {
    fn row(&self, result: &'static str, upids: Vec<String>, detail: Option<Value>) -> Row {
        Row {
            ts: now_rfc3339(),
            req: self.req.to_string(),
            client_ip: self.client_ip,
            action: self.action.to_string(),
            vmid: self.vmid.to_string(),
            dry_run: Some(false),
            result,
            upids,
            outcome: None,
            error: None,
            detail,
        }
    }
}

impl Recorder for AuditRec<'_> {
    fn started(&self) -> Result<(), String> {
        let row = self.row("started", vec![], self.detail.clone());
        self.st.audit.write_synced(&row).map_err(|e| {
            tracing::error!("audit log write failed: {e}");
            e.to_string()
        })
    }

    fn task(&self, call: &Call, upid: &str) -> Result<(), String> {
        let row = self.row(
            "task",
            vec![upid.to_string()],
            Some(json!({"method": call.method, "path": call.path})),
        );
        self.st.audit.write_synced(&row).map_err(|e| {
            tracing::error!("audit log write failed: {e}");
            e.to_string()
        })
    }
}

/// JSON bodies only. A cross-site form can send `text/plain` or
/// `x-www-form-urlencoded` without a CORS preflight, but not
/// `application/json`, and nothing here answers a preflight.
async fn control_route(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((vmid_raw, action_raw)): Path<(String, String)>,
    body: Result<Json<ControlRequest>, JsonRejection>,
) -> Response {
    let client_ip = peer.ip().to_canonical();
    let req_id = request_id();
    let action_name: String = action_raw.chars().take(32).collect();
    let vmid_shown: String = vmid_raw.chars().take(32).collect();
    // Unknown until the body parses.
    let dry_run_hint = body.as_ref().ok().map(|b| b.dry_run);

    let refuse = |code: StatusCode, why: String| {
        let row = Row {
            ts: now_rfc3339(),
            req: req_id.clone(),
            client_ip,
            action: action_name.clone(),
            vmid: vmid_shown.clone(),
            dry_run: dry_run_hint,
            result: "refused",
            upids: vec![],
            outcome: None,
            error: Some(why.clone()),
            detail: None,
        };
        if let Err(e) = st.audit.write_unsynced(&row) {
            tracing::error!("audit log write failed: {e}");
        }
        // Debug, not Display: these hold percent-decoded request text, which
        // may carry CR/LF meant to forge journal lines.
        tracing::info!(%client_ip, action = ?action_name, vmid = ?vmid_shown, why = ?why, "refused");
        (code, Json(json!({"result": "refused", "error": why}))).into_response()
    };

    let vmid = match Vmid::parse(&vmid_raw) {
        Ok(v) => v,
        Err(e) => return refuse(StatusCode::FORBIDDEN, e.to_string()),
    };
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, e.body_text()),
    };
    if req.confirm_vmid != vmid.get() {
        return refuse(
            StatusCode::BAD_REQUEST,
            format!(
                "confirm_vmid {} does not match VMID {vmid}; type the VMID you mean to act on",
                req.confirm_vmid
            ),
        );
    }
    let action = match Action::parse(&action_raw, req.snapname.as_deref()) {
        Ok(a) => a,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, e),
    };
    let Ok(held) = st.busy.clone().try_lock_owned() else {
        return refuse(
            StatusCode::CONFLICT,
            "another control is still running; wait for it to finish".into(),
        );
    };

    // The control runs in its own task, which owns the lock. hyper drops this
    // handler when the client disconnects mid-response (a reload, a closed
    // tab, Ctrl-C); the control must still run to its end, be recorded, and
    // keep the lock until then.
    let task = tokio::spawn(supervise_control(
        st.clone(),
        held,
        req_id,
        client_ip,
        vmid,
        action,
        req.dry_run,
    ));
    match task.await {
        Ok((code, body)) => (code, Json(body)).into_response(),
        Err(e) => {
            tracing::error!("control supervisor ended abnormally: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"result": "error", "error": "control task ended abnormally"})),
            )
                .into_response()
        }
    }
}

fn action_detail(action: &Action) -> Option<Value> {
    match action {
        Action::SnapshotCreate(s) | Action::SnapshotRollback(s) => {
            Some(json!({"snapname": s.as_str()}))
        }
        _ => None,
    }
}

/// Owns the lock and runs the control in a task of its own, so that a panic
/// in it (library code: nestview's own is built with `deny(clippy::panic)`)
/// still ends with a final audit row and the lock held until that row is
/// written. Without this, unwinding would drop the guard while
/// a PVE task just started may still be running, and leave no final row.
async fn supervise_control(
    st: Arc<AppState>,
    held: tokio::sync::OwnedMutexGuard<()>,
    req_id: String,
    client_ip: IpAddr,
    vmid: Vmid,
    action: Action,
    dry_run: bool,
) -> (StatusCode, Value) {
    let name = action.name();
    let detail = action_detail(&action);
    let inner = tokio::spawn(run_control(
        st.clone(),
        req_id.clone(),
        client_ip,
        vmid,
        action,
        dry_run,
        detail.clone(),
    ));
    let out = match inner.await {
        Ok(out) => out,
        Err(e) => {
            let why = if e.is_panic() {
                "control task panicked"
            } else {
                "control task was cancelled"
            };
            tracing::error!(action = name, %vmid, req = %req_id, "{why}: {e}");
            let row = Row {
                ts: now_rfc3339(),
                req: req_id.clone(),
                client_ip,
                action: name.to_string(),
                vmid: vmid.to_string(),
                dry_run: Some(dry_run),
                result: "error",
                upids: vec![],
                outcome: None,
                error: Some(why.to_string()),
                detail,
            };
            let audit_error = st.audit.write_synced(&row).err().map(|e| e.to_string());
            if let Some(e) = &audit_error {
                tracing::error!("audit log write failed: {e}");
            }
            let body =
                json!({"result": "error", "error": why, "req": req_id, "audit_error": audit_error});
            // Whether a write went out is unknown here: refresh regardless.
            st.kick.notify_one();
            (StatusCode::INTERNAL_SERVER_ERROR, body)
        }
    };
    drop(held);
    out
}

async fn run_control(
    st: Arc<AppState>,
    req_id: String,
    client_ip: IpAddr,
    vmid: Vmid,
    action: Action,
    dry_run: bool,
    detail: Option<Value>,
) -> (StatusCode, Value) {
    tracing::info!(%client_ip, action = action.name(), %vmid, dry_run, req = %req_id, "control");
    let rec = AuditRec {
        st: &st,
        req: &req_id,
        client_ip,
        action: action.name(),
        vmid,
        detail: detail.clone(),
    };
    let report = control::run(
        st.api.as_ref(),
        &st.node,
        vmid,
        &action,
        dry_run,
        st.task_timeout,
        &rec,
    )
    .await;
    let row = Row {
        ts: now_rfc3339(),
        req: req_id.clone(),
        client_ip,
        action: action.name().to_string(),
        vmid: vmid.to_string(),
        dry_run: Some(dry_run),
        result: report.result.as_str(),
        upids: report
            .writes
            .iter()
            .filter_map(|w| w.upid.clone())
            .collect(),
        outcome: report.writes.iter().rev().find_map(|w| w.outcome.clone()),
        error: report.error.clone(),
        detail,
    };
    let audit_error = st.audit.write_synced(&row).err().map(|e| e.to_string());
    if let Some(e) = &audit_error {
        tracing::error!("audit log write failed: {e}");
    }
    tracing::info!(
        action = action.name(),
        %vmid,
        req = %req_id,
        result = report.result.as_str(),
        error = ?report.error.as_deref().unwrap_or(""),
        "control finished"
    );
    if report.writes.iter().any(|w| w.sent) {
        st.kick.notify_one();
    }
    let code = match report.result {
        ActionResult::Ok
        | ActionResult::DryRun
        | ActionResult::Warnings
        | ActionResult::Failed
        | ActionResult::TimedOut => StatusCode::OK,
        ActionResult::Refused => StatusCode::CONFLICT,
        ActionResult::Error => StatusCode::BAD_GATEWAY,
        ActionResult::AuditFailed => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut body = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
    if let Some(obj) = body.as_object_mut() {
        obj.insert("req".into(), json!(req_id));
        if let Some(e) = audit_error {
            obj.insert("audit_error".into(), json!(e));
        }
    }
    (code, body)
}

#[cfg(test)]
mod tests;

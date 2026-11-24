//! The guard (peer, Host, Origin, session), login, the allowlist, the confirm
//! step, dry run and the audit trail, through the real router.

use std::io::Write;
use std::sync::Mutex as StdMutex;

use axum::body::{to_bytes, Body};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::Request as HttpRequest;
use concord_pve::{api_path, Method as PveMethod, MockPve};
use serde_json::Value;
use tower::ServiceExt;

use super::*;

#[derive(Clone, Default)]
struct Buf {
    data: Arc<StdMutex<Vec<u8>>>,
    /// When set, every write fails, as on a full disk.
    fail: Arc<StdMutex<bool>>,
    /// How many times the log was synced (once per control row;
    /// never for a refusal).
    syncs: Arc<StdMutex<usize>>,
}

impl crate::audit::Sink for Buf {
    fn sync(&mut self) -> std::io::Result<()> {
        *self.syncs.lock().unwrap() += 1;
        Ok(())
    }
}

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if *self.fail.lock().unwrap() {
            return Err(std::io::Error::other("No space left on device"));
        }
        self.data.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn rows(&self) -> Vec<Value> {
        String::from_utf8(self.data.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn text(&self) -> String {
        String::from_utf8(self.data.lock().unwrap().clone()).unwrap()
    }
}

const OPERATOR: [u8; 4] = [192, 0, 2, 10];
const HOST: &str = "192.0.2.77:8099";
const ORIGIN: &str = "http://192.0.2.77:8099";
const PASS: &str = "correct horse battery staple 42";
const JSON: &str = "application/json";

struct App {
    router: Router,
    audit: Buf,
    state: Arc<AppState>,
}

fn app_from(api: Arc<dyn PveApi>, from: [u8; 4], ttl: Duration) -> App {
    let audit = Buf::default();
    let (_tx, rx) = watch::channel(None);
    let state = Arc::new(AppState {
        api,
        node: Node::new("pve1").unwrap(),
        allowed_clients: vec![IpAddr::from(OPERATOR)],
        allowed_hosts: vec![HOST.to_string()],
        task_timeout: Duration::from_secs(30),
        audit: AuditLog::to_writer(Box::new(audit.clone())),
        snapshot: rx,
        kick: Arc::new(Notify::new()),
        busy: Arc::new(Mutex::new(())),
        passphrase: Passphrase::from_text(PASS).unwrap(),
        sessions: Sessions::new(ttl),
    });
    let router = router(state.clone()).layer(MockConnectInfo(SocketAddr::from((from, 40000))));
    App {
        router,
        audit,
        state,
    }
}

fn app(api: Arc<dyn PveApi>, from: [u8; 4]) -> App {
    app_from(api, from, Duration::from_secs(3600))
}

/// A same-origin request as the dashboard's `fetch()` calls send it (mode
/// `cors`): right Host, the real Origin and Sec-Fetch-Site. A form POST is a
/// navigation and its Origin depends on the referrer policy, so the login
/// form is also tested without this helper, in
/// `browser_form_login_works_under_the_served_referrer_policy`.
fn browser(method: &str, uri: &str) -> axum::http::request::Builder {
    HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
}

async fn send(r: &Router, req: HttpRequest<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = r.clone().oneshot(req).await.unwrap();
    let code = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (code, headers, String::from_utf8_lossy(&bytes).into_owned())
}

async fn login_with(r: &Router, pass: &str) -> (StatusCode, HeaderMap, String) {
    let body = format!("passphrase={}", pass.replace(' ', "+"));
    send(
        r,
        browser("POST", "/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// Logs in and returns the `Cookie` header value to send.
async fn login(r: &Router) -> String {
    let (code, h, _) = login_with(r, PASS).await;
    assert_eq!(code, StatusCode::SEE_OTHER);
    let set = h[header::SET_COOKIE].to_str().unwrap();
    set.split(';').next().unwrap().to_string()
}

async fn post(a: &App, uri: &str, ctype: &str, body: &str) -> (StatusCode, Value) {
    let cookie = login(&a.router).await;
    post_with(&a.router, &cookie, uri, ctype, body).await
}

async fn post_with(
    r: &Router,
    cookie: &str,
    uri: &str,
    ctype: &str,
    body: &str,
) -> (StatusCode, Value) {
    let (code, _, text) = send(
        r,
        browser("POST", uri)
            .header(header::CONTENT_TYPE, ctype)
            .header(header::COOKIE, cookie)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    (
        code,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

// ---------------------------------------------------------------- login

#[tokio::test]
async fn unauthenticated_requests_are_refused_on_every_route() {
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    for (method, uri, want) in [
        ("GET", "/", StatusCode::SEE_OTHER),
        ("GET", "/app.js", StatusCode::UNAUTHORIZED),
        ("GET", "/api/status", StatusCode::UNAUTHORIZED),
        ("POST", "/api/vm/9001/stop", StatusCode::UNAUTHORIZED),
        ("POST", "/logout", StatusCode::UNAUTHORIZED),
    ] {
        let (code, h, _) = send(
            &a.router,
            browser(method, uri)
                .header(header::CONTENT_TYPE, JSON)
                .header(header::COOKIE, "nestview_session=deadbeef")
                .body(Body::from(r#"{"confirm_vmid": 9001, "dry_run": false}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{method} {uri}");
        if uri == "/" {
            assert_eq!(h[header::LOCATION], "/login");
        }
    }
    assert!(api.calls().is_empty());
    // The refused control is audited, with dry_run unknown.
    let rows = a.audit.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["result"], "refused");
    assert_eq!(rows[0]["error"], "not logged in");
    assert_eq!(rows[0]["vmid"], "9001");
    assert_eq!(rows[0]["action"], "stop");
    assert!(rows[0]["dry_run"].is_null());

    // The login page and its stylesheet need no session.
    for uri in ["/login", "/app.css"] {
        let (code, _, _) = send(&a.router, browser("GET", uri).body(Body::empty()).unwrap()).await;
        assert_eq!(code, StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn login_sets_a_strict_session_cookie_that_opens_the_api() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    let (code, h, _) = login_with(&a.router, PASS).await;
    assert_eq!(code, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/");
    let set = h[header::SET_COOKIE].to_str().unwrap();
    assert!(set.starts_with("nestview_session="));
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
    assert!(set.contains("Max-Age=3600"));
    let cookie = set.split(';').next().unwrap();

    // 503: authenticated, and no poll has run in this test.
    let (code, _, _) = send(
        &a.router,
        browser("GET", "/api/status")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);

    // Logging out ends the session.
    let (code, _, _) = send(
        &a.router,
        browser("POST", "/logout")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    let (code, _, _) = send(
        &a.router,
        browser("GET", "/api/status")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_passphrase_is_refused_and_limited() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    for _ in 0..5 {
        let (code, h, body) = login_with(&a.router, "not the passphrase at all").await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(!h.contains_key(header::SET_COOKIE));
        assert!(body.contains("Wrong passphrase"));
    }
    // Locked out: even the right passphrase is not accepted for now.
    let (code, h, _) = login_with(&a.router, PASS).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert!(!h.contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn expired_session_is_refused() {
    let a = app_from(Arc::new(MockPve::new()), OPERATOR, Duration::ZERO);
    let cookie = login(&a.router).await;
    let (code, _, _) = send(
        &a.router,
        browser("GET", "/api/status")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passphrase_never_reaches_debug_responses_or_audit() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    assert!(!format!("{:?}", a.state.passphrase).contains(PASS));
    let (_, h, body) = login_with(&a.router, PASS).await;
    assert!(!format!("{h:?}").contains(PASS) && !body.contains(PASS));
    let (_, h, body) = login_with(&a.router, &format!("{PASS}x")).await;
    assert!(!format!("{h:?}").contains(PASS) && !body.contains(PASS));
    // A malformed form is refused without echoing what was sent.
    let (code, _, body) = send(
        &a.router,
        browser("POST", "/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("pass={}", PASS.replace(' ', "+"))))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(!body.contains("horse"));
    assert!(!a.audit.text().contains("horse"));
}

/// The `Origin` a browser sends on a form POST (mode `navigate`, not `cors`)
/// from this dashboard to itself, following the Fetch standard's "serializing
/// a request origin": for a non-CORS request the referrer policy decides.
fn form_post_origin(referrer_policy: &str) -> &'static str {
    match referrer_policy {
        "no-referrer" => "null",
        // These null it only cross-origin, or from https to http; neither
        // applies to http://CT_IP:8099 posting to itself.
        "same-origin"
        | "origin"
        | "strict-origin"
        | "origin-when-cross-origin"
        | "strict-origin-when-cross-origin"
        | "no-referrer-when-downgrade"
        | "unsafe-url" => ORIGIN,
        other => panic!("unknown referrer policy {other:?}"),
    }
}

/// Pinned, because going back to `no-referrer` makes every
/// browser send `Origin: null` on the login form and silently breaks login.
#[tokio::test]
async fn referrer_policy_is_same_origin_everywhere() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    let cookie = login(&a.router).await;
    for (method, uri, cookie) in [
        ("GET", "/login", ""),
        ("GET", "/app.css", ""),
        ("GET", "/", cookie.as_str()),
        ("GET", "/", ""),
        ("GET", "/api/status", ""),
    ] {
        let (_, h, _) = send(
            &a.router,
            browser(method, uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(h[header::REFERRER_POLICY], "same-origin", "{method} {uri}");
    }
    assert_eq!(REFERRER_POLICY, "same-origin");
}

/// The login form as a browser submits it, built from the
/// headers the login page is actually served with, not from `browser()`.
#[tokio::test]
async fn browser_form_login_works_under_the_served_referrer_policy() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    // Typing the URL: a navigation GET, which carries no Origin.
    let (code, h, html) = send(
        &a.router,
        HttpRequest::builder()
            .method("GET")
            .uri("/login")
            .header(header::HOST, HOST)
            .header("sec-fetch-site", "none")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(html.contains(r#"<form method="post" action="login">"#));
    let policy = h[header::REFERRER_POLICY].to_str().unwrap().to_string();

    let submit = |origin: &str| {
        let mut b = HttpRequest::builder()
            .method("POST")
            .uri("/login")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, origin)
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-user", "?1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if origin != "null" {
            b = b.header(header::REFERER, format!("{ORIGIN}/login"));
        }
        b.body(Body::from(format!("passphrase={}", PASS.replace(' ', "+"))))
            .unwrap()
    };

    let (code, h, body) = send(&a.router, submit(form_post_origin(&policy))).await;
    assert_eq!(code, StatusCode::SEE_OTHER, "policy {policy:?}: {body}");
    assert!(h[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .starts_with("nestview_session="));

    // What `no-referrer` would have made the browser send stays refused:
    // `null` is also what a sandboxed or opaque-origin page sends.
    let (code, h, _) = send(&a.router, submit(form_post_origin("no-referrer"))).await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert!(!h.contains_key(header::SET_COOKIE));
}

// ------------------------------------------------- Host, Origin, peer

#[tokio::test]
async fn wrong_host_is_refused_on_every_route() {
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    let cookie = login(&a.router).await;
    for (method, uri) in [
        ("GET", "/"),
        ("GET", "/login"),
        ("GET", "/app.css"),
        ("GET", "/api/status"),
        ("POST", "/login"),
        ("POST", "/api/vm/9001/stop"),
    ] {
        for host in ["evil.example:8099", "192.0.2.77", "localhost:8099"] {
            let (code, _, _) = send(
                &a.router,
                HttpRequest::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::HOST, host)
                    .header(header::ORIGIN, format!("http://{host}"))
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, JSON)
                    .body(Body::from(r#"{"confirm_vmid": 9001, "dry_run": false}"#))
                    .unwrap(),
            )
            .await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{method} {uri} Host {host}");
        }
    }
    assert!(api.calls().is_empty());
}

#[tokio::test]
async fn posts_need_a_same_origin_origin() {
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    let cookie = login(&a.router).await;
    let body = r#"{"confirm_vmid": 9001, "dry_run": true}"#;
    for (origin, site) in [
        (None, None),
        (Some("http://evil.example"), None),
        (Some("https://192.0.2.77:8099"), None),
        (Some("null"), None),
        (Some(ORIGIN), Some("cross-site")),
        (Some(ORIGIN), Some("same-site")),
        (Some(ORIGIN), Some("none")),
    ] {
        let mut b = HttpRequest::builder()
            .method("POST")
            .uri("/api/vm/9001/stop")
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, JSON);
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        if let Some(s) = site {
            b = b.header("sec-fetch-site", s);
        }
        let (code, _, text) = send(&a.router, b.body(Body::from(body)).unwrap()).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{origin:?} {site:?}: {text}");
    }
    assert!(api.calls().is_empty());
    assert!(a.audit.rows().iter().all(|r| r["result"] == "refused"));

    // A login POST from a foreign origin is refused too.
    let (code, h, _) = send(
        &a.router,
        HttpRequest::builder()
            .method("POST")
            .uri("/login")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, "http://evil.example")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("passphrase={}", PASS.replace(' ', "+"))))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert!(!h.contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn other_clients_get_403_on_every_route_and_controls_are_audited() {
    for (method, uri) in [
        ("GET", "/"),
        ("GET", "/login"),
        ("GET", "/api/status"),
        ("POST", "/api/vm/9001/stop"),
    ] {
        let api = Arc::new(MockPve::new());
        let a = app(api.clone(), [192, 0, 2, 50]);
        let (code, _, _) = send(
            &a.router,
            browser(method, uri)
                .header(header::CONTENT_TYPE, JSON)
                .body(Body::from(r#"{"confirm_vmid": 9001, "dry_run": false}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{uri}");
        assert!(api.calls().is_empty());
        let rows = a.audit.rows();
        if method == "POST" {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["client_ip"], "192.0.2.50");
            assert_eq!(rows[0]["error"], "client address not allowed");
        } else {
            assert!(rows.is_empty());
        }
    }
}

// ------------------------------------------------------- the control

#[tokio::test]
async fn vmids_outside_the_allowlist_are_refused_and_never_reach_pve() {
    for vmid in [
        "9004",
        "100",
        "9000",
        "09001",
        "+9001",
        "9001.0",
        "abc",
        "4294967297",
    ] {
        let api = Arc::new(MockPve::new());
        let a = app(api.clone(), OPERATOR);
        let body = r#"{"confirm_vmid": 9004, "dry_run": false}"#;
        let (code, v) = post(&a, &format!("/api/vm/{vmid}/stop"), JSON, body).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{vmid}: {v}");
        assert_eq!(v["result"], "refused");
        assert!(api.calls().is_empty(), "{vmid} reached PVE");
        let rows = a.audit.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["result"], "refused");
        assert_eq!(rows[0]["action"], "stop");
        assert_eq!(rows[0]["client_ip"], "192.0.2.10");
        assert_eq!(rows[0]["dry_run"], false);
    }
}

#[test]
fn allowlist_is_exactly_the_three_nodes() {
    for id in 0..=20_000u32 {
        assert_eq!(Vmid::new(id).is_ok(), (9001..=9003).contains(&id), "{id}");
    }
    assert!(Vmid::new(u32::MAX).is_err());
}

#[tokio::test]
async fn confirm_vmid_must_match_the_path() {
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    let (code, v) = post(
        &a,
        "/api/vm/9001/kill",
        JSON,
        r#"{"confirm_vmid": 9002, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("does not match"));
    assert!(api.calls().is_empty());
    assert_eq!(a.audit.rows()[0]["result"], "refused");
    assert_eq!(a.audit.rows()[0]["vmid"], "9001");

    // Missing confirm_vmid, or a body that is not JSON, is refused the same
    // way, and the row does not claim a dry_run value it never read.
    for (ctype, body) in [
        (JSON, r#"{"dry_run": true}"#),
        (JSON, r#"{"confirm_vmid": 9001}"#),
        ("text/plain", r#"{"confirm_vmid": 9001, "dry_run": false}"#),
        (
            "application/x-www-form-urlencoded",
            "confirm_vmid=9001&dry_run=false",
        ),
    ] {
        let api = Arc::new(MockPve::new());
        let a = app(api.clone(), OPERATOR);
        let (code, _) = post(&a, "/api/vm/9001/kill", ctype, body).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{ctype} {body}");
        assert!(api.calls().is_empty());
        let row = &a.audit.rows()[0];
        assert_eq!(row["result"], "refused");
        assert!(row["dry_run"].is_null(), "{row}");
    }
}

#[tokio::test]
async fn refusal_log_text_is_not_trusted() {
    // A CR/LF in the path is percent-decoded by the router. It is audited as
    // data (JSON-escaped) and the request is still refused.
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    let (code, _) = post(
        &a,
        "/api/vm/9001%0Aforged/stop",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": true}"#,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(a.audit.rows()[0]["vmid"], "9001\nforged");
    assert_eq!(a.audit.text().lines().count(), 1);
}

/// A host on which 9001 is this estate's nest1. Shapes follow responses
/// captured from a real host.
fn host_9001(state: &str, net0: &str) -> MockPve {
    MockPve::new()
        .on(
            PveMethod::Get,
            "/version",
            serde_json::json!({"version": "9.2.21"}),
        )
        .on(
            PveMethod::Get,
            "/nodes",
            serde_json::json!([{"node": "pve1", "status": "online"}]),
        )
        .on(
            PveMethod::Get,
            "/cluster/resources",
            serde_json::json!([{"vmid": 9001, "name": "nest1", "type": "qemu", "status": state}]),
        )
        .on(
            PveMethod::Get,
            "/nodes/pve1/qemu/9001/config",
            serde_json::json!({"name": "nest1", "tags": "concord-nest", "net0": net0}),
        )
        .on(
            PveMethod::Get,
            "/pools",
            serde_json::json!([{"poolid": "concord-nest", "members": [{"vmid": 9001}]}]),
        )
        .on(
            PveMethod::Get,
            "/nodes/pve1/qemu/9001/status/current",
            serde_json::json!({"status": state, "qmpstatus": state}),
        )
}

const NET0: &str = "virtio=02:00:00:00:00:01,bridge=cnest";

#[tokio::test]
async fn dry_run_returns_the_call_and_sends_nothing() {
    let api = Arc::new(host_9001("running", NET0));
    let a = app(api.clone(), OPERATOR);
    let (code, v) = post(
        &a,
        "/api/vm/9001/snapshot",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": true, "snapname": "pre-test"}"#,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{v}");
    assert_eq!(v["result"], "dry_run");
    assert_eq!(v["writes"][0]["call"]["method"], "POST");
    assert_eq!(
        v["writes"][0]["call"]["path"],
        "/nodes/pve1/qemu/9001/snapshot"
    );
    assert_eq!(v["writes"][0]["call"]["params"][0][0], "snapname");
    assert_eq!(v["writes"][0]["call"]["params"][0][1], "pre-test");
    assert_eq!(v["writes"][0]["sent"], false);
    // The guards ran (GETs only); nothing was written.
    assert_eq!(api.calls().len(), 5);
    assert!(api.calls().iter().all(|c| c.method == PveMethod::Get));
    let rows = a.audit.rows();
    assert_eq!(rows.len(), 1, "a dry run writes no started row");
    assert_eq!(rows[0]["result"], "dry_run");
    assert_eq!(rows[0]["dry_run"], true);
    assert_eq!(rows[0]["detail"]["snapname"], "pre-test");
}

const START_UPID: &str = "UPID:pve1:0000ABCD:0000BEEF:65000000:qmstart:9001:concord@pve!nest:";

fn task_status(upid: &str) -> String {
    api_path(&["nodes", "pve1", "tasks", upid, "status"]).unwrap()
}

#[tokio::test]
async fn real_run_writes_started_task_and_final_rows() {
    let api = Arc::new(
        host_9001("stopped", NET0)
            .on(
                PveMethod::Post,
                "/nodes/pve1/qemu/9001/status/start",
                Value::String(START_UPID.into()),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "stopped", "exitstatus": "OK"}),
            ),
    );
    let a = app(api.clone(), OPERATOR);
    let (code, v) = post(
        &a,
        "/api/vm/9001/start",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{v}");
    assert_eq!(v["result"], "ok");
    let rows = a.audit.rows();
    let results: Vec<&str> = rows.iter().map(|r| r["result"].as_str().unwrap()).collect();
    assert_eq!(results, vec!["started", "task", "ok"]);
    assert_eq!(
        *a.audit.syncs.lock().unwrap(),
        rows.len(),
        "every control row is synced"
    );
    assert!(rows.iter().all(|r| r["req"] == rows[0]["req"]));
    assert_eq!(rows[0]["req"], v["req"]);
    assert_eq!(rows[1]["upids"][0], START_UPID);
    assert_eq!(
        rows[1]["detail"]["path"],
        "/nodes/pve1/qemu/9001/status/start"
    );
    assert_eq!(rows[2]["upids"][0], START_UPID);
    assert_eq!(rows[2]["outcome"], "OK");
    assert_eq!(rows[2]["dry_run"], false);
    assert!(rows[2]["ts"].as_str().unwrap().ends_with('Z'));
}

/// A cross-origin page can make the guard write refusal rows at
/// will, so those must not cost an fsync each. The rows of a control that
/// runs still do.
#[tokio::test]
async fn refusals_are_not_synced_but_control_rows_are() {
    let api = Arc::new(
        host_9001("stopped", NET0)
            .on(
                PveMethod::Post,
                "/nodes/pve1/qemu/9001/status/start",
                Value::String(START_UPID.into()),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "stopped", "exitstatus": "OK"}),
            ),
    );
    let a = app(api.clone(), OPERATOR);

    // What a no-cors form POST from another site looks like: right peer and
    // Host, foreign Origin, no session.
    for _ in 0..5 {
        let (code, _, _) = send(
            &a.router,
            HttpRequest::builder()
                .method("POST")
                .uri("/api/vm/9001/start")
                .header(header::HOST, HOST)
                .header(header::ORIGIN, "http://evil.example")
                .header("sec-fetch-site", "cross-site")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(r#"{"confirm_vmid": 9001, "dry_run": false}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    }
    // A refusal from inside the handler (vmid outside the allowlist).
    let (code, _) = post(
        &a,
        "/api/vm/9004/start",
        JSON,
        r#"{"confirm_vmid": 9004, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let rows = a.audit.rows();
    assert_eq!(rows.len(), 6);
    assert!(rows.iter().all(|r| r["result"] == "refused"));
    assert_eq!(*a.audit.syncs.lock().unwrap(), 0, "refusals are not synced");
    assert!(api.calls().is_empty());

    let (code, v) = post(
        &a,
        "/api/vm/9001/start",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{v}");
    let results: Vec<String> = a.audit.rows()[6..]
        .iter()
        .map(|r| r["result"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(results, vec!["started", "task", "ok"]);
    assert_eq!(*a.audit.syncs.lock().unwrap(), 3, "control rows are synced");
}

#[tokio::test]
async fn audit_failure_refuses_with_500_and_sends_nothing() {
    let api = Arc::new(host_9001("stopped", NET0));
    let a = app(api.clone(), OPERATOR);
    let cookie = login(&a.router).await;
    *a.audit.fail.lock().unwrap() = true;
    let (code, v) = post_with(
        &a.router,
        &cookie,
        "/api/vm/9001/start",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(v["result"], "audit_failed");
    assert!(api.calls().iter().all(|c| c.method == PveMethod::Get));
}

/// The client goes away while a restore waits on its start task.
/// The restore still finishes (the un-sever PUT is sent), the lock is held
/// until then, and the audit trail is complete.
#[tokio::test(start_paused = true)]
async fn client_disconnect_does_not_cancel_a_control() {
    let severed = format!("{NET0},link_down=1");
    let api = Arc::new(
        host_9001("stopped", &severed)
            .on(
                PveMethod::Post,
                "/nodes/pve1/qemu/9001/status/start",
                Value::String(START_UPID.into()),
            )
            // Running for several polls (1 s apart), then done.
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "running"}),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "running"}),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "running"}),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "running"}),
            )
            .on(
                PveMethod::Get,
                &task_status(START_UPID),
                serde_json::json!({"status": "stopped", "exitstatus": "OK"}),
            )
            .on(PveMethod::Put, "/nodes/pve1/qemu/9001/config", Value::Null),
    );
    let a = app(api.clone(), OPERATOR);
    let cookie = login(&a.router).await;
    let body = r#"{"confirm_vmid": 9001, "dry_run": false}"#;
    let req = browser("POST", "/api/vm/9001/restore")
        .header(header::CONTENT_TYPE, JSON)
        .header(header::COOKIE, &cookie)
        .body(Body::from(body))
        .unwrap();

    // What hyper does on EOF: the handler future is dropped mid-wait.
    let handler = a.router.clone().oneshot(req);
    let dropped = tokio::time::timeout(Duration::from_millis(1500), handler).await;
    assert!(dropped.is_err(), "the handler should still be waiting");
    let calls = api.calls();
    assert!(calls
        .iter()
        .any(|c| c.method == PveMethod::Post && c.path.ends_with("/status/start")));
    assert!(!calls.iter().any(|c| c.method == PveMethod::Put));

    // The lock is still held: a second control is refused.
    let (code, _) = post_with(
        &a.router,
        &cookie,
        "/api/vm/9001/stop",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": true}"#,
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT);

    // Let the orphaned control run to its end.
    for _ in 0..100 {
        if a.audit.rows().iter().any(|r| r["result"] == "ok") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let put = api
        .calls()
        .into_iter()
        .find(|c| c.method == PveMethod::Put)
        .expect("the un-sever PUT was sent");
    assert_eq!(put.params, vec![("net0".to_string(), NET0.to_string())]);
    let results: Vec<String> = a
        .audit
        .rows()
        .iter()
        .filter(|r| r["action"] == "restore")
        .map(|r| r["result"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(results, vec!["started", "task", "ok"]);
    assert!(a.state.busy.try_lock().is_ok(), "lock released at the end");
}

/// Passes reads to a MockPve and panics on the first write, as a library bug
/// inside a control would.
struct PanicOnWrite(MockPve);

#[async_trait::async_trait]
impl PveApi for PanicOnWrite {
    async fn request(
        &self,
        method: PveMethod,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Value, concord_pve::PveError> {
        if method != PveMethod::Get {
            panic!("simulated library panic on {} {path}", method.as_str());
        }
        self.0.request(method, path, params).await
    }
}

/// A panic inside the control still leaves a final `error` row
/// with the request's id, kicks the poller, and frees the lock only after
/// that row is written.
#[tokio::test]
async fn panic_in_a_control_is_recorded_and_releases_the_lock_after() {
    let a = app(Arc::new(PanicOnWrite(host_9001("stopped", NET0))), OPERATOR);
    let (code, v) = post(
        &a,
        "/api/vm/9001/start",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": false}"#,
    )
    .await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(v["result"], "error");
    assert_eq!(v["error"], "control task panicked");
    let rows = a.audit.rows();
    let results: Vec<&str> = rows.iter().map(|r| r["result"].as_str().unwrap()).collect();
    assert_eq!(results, vec!["started", "error"]);
    assert_eq!(rows[1]["req"], rows[0]["req"]);
    assert_eq!(rows[1]["req"], v["req"]);
    assert_eq!(rows[1]["error"], "control task panicked");
    assert_eq!(rows[1]["action"], "start");
    assert_eq!(rows[1]["dry_run"], false);
    assert!(a.state.busy.try_lock().is_ok(), "lock released at the end");
    tokio::time::timeout(Duration::from_secs(1), a.state.kick.notified())
        .await
        .expect("the poller was kicked");

    // The next control runs normally.
    let (code, v) = post(
        &a,
        "/api/vm/9001/start",
        JSON,
        r#"{"confirm_vmid": 9001, "dry_run": true}"#,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{v}");
    assert_eq!(v["result"], "dry_run");
}

// ------------------------------------------------------------- misc

#[tokio::test]
async fn no_route_proxies_arbitrary_paths() {
    let api = Arc::new(MockPve::new());
    let a = app(api.clone(), OPERATOR);
    let cookie = login(&a.router).await;
    for uri in [
        "/api/vm/9001/status/current",
        "/api2/json/nodes",
        "/api/vm/9001/../../access/users",
        "/api/proxy?path=/nodes",
    ] {
        let (code, _, _) = send(
            &a.router,
            browser("GET", uri)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(
            code == StatusCode::NOT_FOUND || code == StatusCode::METHOD_NOT_ALLOWED,
            "{uri}: {code}"
        );
    }
    assert!(api.calls().is_empty());
}

#[tokio::test]
async fn ui_is_served_with_a_strict_csp() {
    let a = app(Arc::new(MockPve::new()), OPERATOR);
    let cookie = login(&a.router).await;
    let (code, h, html) = send(
        &a.router,
        browser("GET", "/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("form-action 'none'"));
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "no external assets"
    );

    // The login page: a same-origin form, no script.
    let (_, h, html) = send(
        &a.router,
        browser("GET", "/login").body(Body::empty()).unwrap(),
    )
    .await;
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("form-action 'self'") && !csp.contains("script-src"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("http://") && !html.contains("https://"));
}

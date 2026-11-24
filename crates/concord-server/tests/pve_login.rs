//! Signing in as a tracked host's root, against fake PVE hosts over real TLS.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use concord_inventory::{InventoryConfig, Poller};
use concord_pve::{Fingerprint, RootLogin};
use concord_server::users::{Role, Users};
use concord_server::{router, AppState, Auth, AuthConfig};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PASS: &str = "s3cret & p%ss=w\u{f6}rd";
const FORM_PASS: &str = "s3cret%20%26%20p%25ss%3Dw%C3%B6rd";
const FULL: &str = "PVE:root@pam:65000000::ZnVsbA";
const HALF: &str = "PVE:!tfa!{%22totp%22%3Atrue,%22recovery%22%3A[0,1]}:65000000::aGFsZg";
const WEBAUTHN: &str = "PVE:!tfa!{%22webauthn%22%3A{}}:65000000::aGFsZg";

#[derive(Clone, Copy)]
enum Mode {
    Plain,
    Tfa,
    WebauthnOnly,
    /// Half a ticket, not marked as one.
    Sly,
    Hang,
    Oversize,
    Redirect,
}

struct Fake {
    addr: SocketAddr,
    pin: Fingerprint,
    seen: Arc<Mutex<Vec<String>>>,
}

fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn ticket(t: &str, tfa: bool) -> String {
    let mut d = json!({"username": "root@pam", "ticket": t, "CSRFPreventionToken": "csrf-value"});
    if tfa {
        d["NeedTFA"] = json!(1);
    }
    http("200 OK", &json!({ "data": d }).to_string())
}

fn answer(mode: Mode, req: &str) -> String {
    let refused = http("401 authentication failure", "");
    if !req.starts_with("POST /api2/json/access/ticket ") {
        return refused;
    }
    let body = req.split("\r\n\r\n").nth(1).unwrap_or_default();
    if body.contains("tfa-challenge=PVE%3A%21tfa%21") {
        let ok = ["totp%3A123456", "recovery%3Aab12%2Dcd34"]
            .iter()
            .any(|c| body.contains(&format!("&password={c}&")));
        return if ok { ticket(FULL, false) } else { refused };
    }
    if body != format!("username=root%40pam&password={FORM_PASS}") {
        return refused;
    }
    match mode {
        Mode::Plain | Mode::Hang => ticket(FULL, false),
        Mode::Tfa => ticket(HALF, true),
        Mode::WebauthnOnly => ticket(WEBAUTHN, true),
        Mode::Sly => ticket(HALF, false),
        Mode::Oversize => http("200 OK", &" ".repeat(70_000)),
        Mode::Redirect => {
            "HTTP/1.1 307 x\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n".into()
        }
    }
}

async fn fake(mode: Mode) -> Fake {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = ck.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.into())
        .expect("cert");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                let req = loop {
                    let Ok(n @ 1..) = tls.read(&mut buf).await else {
                        return;
                    };
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        continue;
                    };
                    let want = head
                        .lines()
                        .filter_map(|l| l.split_once(": "))
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map_or(0, |(_, v)| v.parse().unwrap_or(0));
                    if body.len() >= want {
                        break text;
                    }
                };
                log.lock().expect("lock").push(req.clone());
                if matches!(mode, Mode::Hang) {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                let _ = tls.write_all(answer(mode, &req).as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Fake {
        addr,
        pin: Fingerprint::of_der(der.as_ref()),
        seen,
    }
}

impl Fake {
    fn login(&self) -> RootLogin {
        self.pinned(self.pin)
    }
    fn pinned(&self, pin: Fingerprint) -> RootLogin {
        let url = format!("https://{}", self.addr).parse().expect("url");
        RootLogin::new(&url, pin, Duration::from_millis(1500)).expect("login")
    }
    fn count(&self) -> usize {
        self.seen.lock().expect("lock").len()
    }
}

struct Server {
    base: String,
    client: Client,
    _dir: tempfile::TempDir,
}

async fn server(pve: Vec<(&str, RootLogin)>, tweak: impl FnOnce(&mut AuthConfig)) -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tmp");
    let users = dir.path().join("users.toml");
    Users::add_user(&users, "user1@pve", Role::ReadOnly, "correct horse battery").expect("user");
    let mut cfg = AuthConfig::new(users, false);
    cfg.pve = pve.into_iter().map(|(n, l)| (n.to_string(), l)).collect();
    cfg.pve_floor = Duration::from_millis(300);
    tweak(&mut cfg);
    let (_, inventory) = Poller::new(Vec::new(), InventoryConfig::default());
    let app = router(AppState { inventory }, Auth::new(cfg).expect("auth"));
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", l.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(l, app).await });
    Server {
        base,
        client: Client::builder().no_proxy().build().expect("client"),
        _dir: dir,
    }
}

impl Server {
    async fn post(&self, body: Value) -> Response {
        self.client
            .post(format!("{}/api/v1/session", self.base))
            .json(&body)
            .send()
            .await
            .expect("resp")
    }
    async fn login(&self, user: &str, pass: &str) -> Response {
        self.post(json!({"username": user, "password": pass})).await
    }
    async fn challenge(&self) -> String {
        let r = self.login("root@pve1", PASS).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers().get("set-cookie").is_none());
        let b: Value = r.json().await.expect("json");
        assert_eq!(b["tfa"], json!(["totp", "recovery"]));
        assert!(!b.to_string().contains("PVE:"));
        b["challenge"].as_str().expect("id").to_string()
    }
    async fn tfa(&self, id: &str, answer: &str) -> Response {
        self.post(json!({"challenge": id, "tfa": answer})).await
    }
}

#[tokio::test]
async fn right_password_opens_an_admin_session_and_goes_to_one_host() {
    let (a, b) = (fake(Mode::Plain).await, fake(Mode::Plain).await);
    let s = server(vec![("pve1", a.login()), ("pve2", b.login())], |_| {}).await;
    let r = s.login("root@pve1", PASS).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let set = r.headers()["set-cookie"].to_str().expect("str").to_string();
    assert!(set.contains("Max-Age=7200"), "{set}");
    assert!(r.bytes().await.expect("body").is_empty());
    let who: Value = s
        .client
        .request(Method::GET, format!("{}/api/v1/session", s.base))
        .header("cookie", set.split(';').next().expect("cookie"))
        .send()
        .await
        .expect("resp")
        .json()
        .await
        .expect("json");
    assert_eq!(
        who,
        json!({"user": "root@pve1", "role": "admin", "source": "pve"})
    );
    assert_eq!((a.count(), b.count()), (1, 0));
    let req = a.seen.lock().expect("lock")[0].to_lowercase();
    assert!(!req.contains("authorization:") && !req.contains("cookie:"));
}

#[tokio::test]
async fn wrong_password_and_unknown_host_look_alike() {
    let a = fake(Mode::Plain).await;
    let s = server(vec![("pve1", a.login())], |_| {}).await;
    let mut bodies = Vec::new();
    for u in ["root@pve1", "root@nope", "root@PVE1"] {
        let t = Instant::now();
        let r = s.login(u, "wrong").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(t.elapsed() >= Duration::from_millis(300), "{u}");
        bodies.push(r.text().await.expect("text"));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    // Not root, so nobody a host is asked about.
    assert_eq!(s.login("user9@pve1", PASS).await.status(), 401);
    assert_eq!(a.count(), 1);
    // The same throttle for all of them.
    assert_eq!(s.login("root@nope", PASS).await.status(), 401);
    assert_eq!(s.login("root@pve1", PASS).await.status(), 429);
    assert_eq!(a.count(), 1, "throttled before any host is asked");
}

#[tokio::test]
async fn hosts_that_cannot_be_trusted_or_reached_are_503() {
    let a = fake(Mode::Plain).await;
    let wrong = a.pinned(Fingerprint::of_der(b"other"));
    let (h, o, r) = (
        fake(Mode::Hang).await,
        fake(Mode::Oversize).await,
        fake(Mode::Redirect).await,
    );
    let sly = fake(Mode::Sly).await;
    let s = server(
        vec![
            ("wrong", wrong),
            ("hang", h.login()),
            ("big", o.login()),
            ("redir", r.login()),
            ("sly", sly.login()),
        ],
        |_| {},
    )
    .await;
    let t = Instant::now();
    for n in ["wrong", "hang", "big", "redir", "sly"] {
        let resp = s.login(&format!("root@{n}"), PASS).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{n}");
        assert!(resp.headers().get("set-cookie").is_none());
        let b: Value = resp.json().await.expect("json");
        assert_eq!(b["code"], "host_unreachable", "{n}");
    }
    assert!(t.elapsed() < Duration::from_secs(8));
    assert_eq!(a.count(), 0, "nothing sent past a wrong certificate");
    assert_eq!(r.count(), 1, "redirect not followed");
    // Not refunded.
    assert_eq!(s.login("root@hang", PASS).await.status(), 429);
}

#[tokio::test]
async fn a_hung_host_does_not_hold_up_others() {
    let (h, a) = (fake(Mode::Hang).await, fake(Mode::Plain).await);
    let s = Arc::new(server(vec![("hang", h.login()), ("pve1", a.login())], |_| {}).await);
    for _ in 0..3 {
        let s = s.clone();
        tokio::spawn(async move { s.login("root@hang", PASS).await });
    }
    while h.count() < 3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let t = Instant::now();
    assert_eq!(s.login("root@pve1", PASS).await.status(), 204);
    let local = s.login("user1@pve", "correct horse battery").await;
    assert_eq!(local.status(), 204);
    assert!(t.elapsed() < Duration::from_secs(1) + Duration::from_millis(400));
}

#[tokio::test]
async fn second_factor_good_bad_replayed_and_expired() {
    let a = fake(Mode::Tfa).await;
    let s = server(vec![("pve1", a.login())], |_| {}).await;
    let id = s.challenge().await;
    assert_eq!(s.tfa(&id, "totp:123456").await.status(), 204);
    let n = a.count();
    assert_eq!(s.tfa(&id, "totp:123456").await.status(), 401, "replayed");
    assert_eq!(a.count(), n);
    // A success gives back both its attempts; four are left here.
    let id = s.challenge().await;
    assert_eq!(s.tfa(&id, "recovery:ab12-cd34").await.status(), 204);
    let id = s.challenge().await;
    let r = s.tfa(&id, "totp:000000").await;
    assert_eq!(r.status(), 401);
    assert!(r.headers().get("set-cookie").is_none());
    assert_eq!(s.tfa(&id, "totp:123456").await.status(), 401, "one answer");

    let s = server(vec![("pve1", a.login())], |c| {
        c.challenge_life = Duration::from_millis(50);
    })
    .await;
    let id = s.challenge().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let n = a.count();
    assert_eq!(s.tfa(&id, "totp:123456").await.status(), 401, "expired");
    assert_eq!(a.count(), n);
}

#[tokio::test]
async fn webauthn_only_is_said_to_be_unsupported() {
    let a = fake(Mode::WebauthnOnly).await;
    let s = server(vec![("pve1", a.login())], |_| {}).await;
    let r = s.login("root@pve1", PASS).await;
    assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(r.headers().get("set-cookie").is_none());
    let b: Value = r.json().await.expect("json");
    assert_eq!(b["code"], "tfa_not_supported");
    assert!(b.get("challenge").is_none());
}

#[tokio::test]
async fn switched_off_is_an_ordinary_unknown_user() {
    let text = include_str!("../../../concord.example.toml");
    let on = concord_config::Config::parse(text).expect("cfg");
    let t = Duration::from_secs(1);
    assert_eq!(on.build_root_logins(t).expect("logins").len(), 2);
    let off = text.replace("# pve_root_login = true", "pve_root_login = false");
    let off = concord_config::Config::parse(&off).expect("cfg");
    assert!(off.build_root_logins(t).expect("logins").is_empty());
    let s = server(Vec::new(), |_| {}).await;
    assert_eq!(s.login("root@pve1", PASS).await.status(), 401);
}

#[tokio::test]
async fn an_existing_local_user_by_that_name_goes_first() {
    let a = fake(Mode::Plain).await;
    let s = server(vec![("pve1", a.login())], |c| {
        let f = c.users_file.clone();
        // From before such names were refused.
        let old = std::fs::read_to_string(&f).expect("read");
        std::fs::write(&f, old.replace("user1@pve", "root@pve1")).expect("write");
    })
    .await;
    assert_eq!(s.login("root@pve1", PASS).await.status(), 401);
    let r = s.login("root@pve1", "correct horse battery").await;
    assert_eq!(r.status(), 204);
    assert_eq!(a.count(), 0, "a local user's password goes to no host");
}

#[tokio::test]
async fn bodies_that_mix_the_two_steps_are_refused() {
    let s = server(Vec::new(), |_| {}).await;
    for b in [
        json!({"username": "a", "password": "b", "challenge": "c"}),
        json!({"username": "a", "tfa": "c"}),
        json!({}),
    ] {
        assert_eq!(s.post(b).await.status(), 422);
    }
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Global, as other tests in other threads would otherwise have the callsites
// cached as of no interest. It then sees their logs too, which is no harm.
#[tokio::test]
async fn nothing_secret_is_logged() {
    let log = Log::default();
    let sink = log.clone();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    tracing::subscriber::set_global_default(sub).expect("only here");
    let (a, t, o) = (
        fake(Mode::Plain).await,
        fake(Mode::Tfa).await,
        fake(Mode::Sly).await,
    );
    let s = server(
        vec![("pve2", a.login()), ("pve1", t.login()), ("sly", o.login())],
        |_| {},
    )
    .await;
    s.login("root@pve2", PASS).await;
    s.login("root@sly", PASS).await;
    s.login("root@hunter2-typed-here", "wrong-pass-value").await;
    let id = s.challenge().await;
    s.tfa(&id, "totp:123456").await;
    let text = String::from_utf8_lossy(&log.0.lock().expect("lock")).to_string();
    assert!(
        text.contains("root@pve2") && text.contains("login refused"),
        "{text}"
    );
    for secret in [
        PASS,
        FORM_PASS,
        "PVE:",
        "PVE%3A",
        "csrf-value",
        "totp:123456",
        "totp%3A123456",
        &id,
        "hunter2",
        "wrong-pass-value",
    ] {
        assert!(!text.contains(secret), "logged {secret}");
    }
}

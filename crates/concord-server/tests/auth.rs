//! Authentication, authorisation and transport rules, over real sockets.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Extension, Router};
use concord_config::Config;
use concord_inventory::{InventoryConfig, Poller};
use concord_server::cli::{manage, Command, TokenCommand, UserCommand};
use concord_server::serve::{serve, Limits};
use concord_server::tls::{self, Tls};
use concord_server::users::{Role, Users};
use concord_server::{guard_host, router_with, AppState, Auth, AuthConfig, Identity};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const PASS: &str = "correct horse battery";

struct Server {
    addr: SocketAddr,
    base: String,
    client: Client,
    users: PathBuf,
    stop: watch::Sender<bool>,
    done: tokio::task::JoinHandle<std::io::Result<()>>,
    _dir: tempfile::TempDir,
}

fn config(dir: &std::path::Path, listen: &str) -> Config {
    let text = include_str!("../../../concord.example.toml").replace("127.0.0.1:8010", listen);
    let mut cfg = Config::parse(&text).expect("cfg");
    cfg.state_dir = dir.join("state");
    cfg
}

fn make_tls(dir: &std::path::Path) -> Tls {
    tls::setup(&config(dir, "192.0.2.10:8010"))
        .expect("tls")
        .expect("https beyond loopback")
}

async fn start(https: bool, limits: Limits) -> Server {
    let dir = tempfile::tempdir().expect("tmp");
    let users = dir.path().join("users.toml");
    Users::add_user(&users, "user2@pve", Role::Admin, PASS).expect("user");
    Users::add_user(&users, "user1@pve", Role::ReadOnly, PASS).expect("user");
    let tls = https.then(|| make_tls(dir.path()));
    let mut b = Client::builder().no_proxy();
    if let Some(t) = &tls {
        b = b.use_preconfigured_tls(
            concord_pve::pinned_client_config(t.fingerprint).expect("client"),
        );
    } else {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let (_, inventory) = Poller::new(Vec::new(), InventoryConfig::default());
    let extra = Router::new()
        .route(
            "/api/v1/test",
            post(|Extension(w): Extension<Identity>| async move { w.user })
                .put(|| async {})
                .delete(|| async {})
                .get(|| async {}),
        )
        .route(
            "/api/v1/slow",
            get(|| tokio::time::sleep(Duration::from_secs(60))),
        );
    let auth = Auth::new(AuthConfig::new(users.clone(), https)).expect("auth");
    let app = router_with(AppState { inventory }, auth, extra);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = guard_host(app, addr);
    let (stop, rx) = watch::channel(false);
    let done = tokio::spawn(async move { serve(listener, app, tls.as_ref(), limits, rx).await });
    Server {
        addr,
        base: format!("{}://{addr}", if https { "https" } else { "http" }),
        client: b.build().expect("client"),
        users,
        stop,
        done,
        _dir: dir,
    }
}

impl Server {
    fn req(&self, m: Method, path: &str) -> RequestBuilder {
        self.client.request(m, format!("{}{path}", self.base))
    }
    async fn status(&self, m: Method, path: &str, headers: &[(&str, &str)]) -> StatusCode {
        let mut r = self.req(m, path);
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.send().await.expect("resp").status()
    }
    async fn try_login(&self, user: &str, pass: &str) -> Response {
        self.req(Method::POST, "/api/v1/session")
            .json(&json!({"username": user, "password": pass}))
            .send()
            .await
            .expect("resp")
    }
    /// The Set-Cookie value, and the Cookie value to send back.
    async fn login(&self, user: &str) -> (String, String) {
        let r = self.try_login(user, PASS).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let set = r.headers()["set-cookie"].to_str().expect("str").to_string();
        let c = set.split(';').next().expect("cookie").to_string();
        (set, c)
    }
}

#[tokio::test]
async fn every_api_path_is_denied_without_identity() {
    let s = start(false, Limits::default()).await;
    for p in [
        "/api",
        "/api/v1/version",
        "/api/v1/estate",
        "/api/v1/hosts",
        "/api/v1/guests",
        "/api/v1/guests/h1/100",
        "/api/v1/session",
        "/api/v1/test",
        "/api/v1/no-such-route",
        "/api/v2/anything",
    ] {
        for m in [Method::GET, Method::POST, Method::DELETE, Method::PATCH] {
            if p.ends_with("/session") && m == Method::POST {
                continue;
            }
            let h = [("x-concord-request", "1")];
            assert_eq!(s.status(m, p, &h).await, StatusCode::UNAUTHORIZED, "{p}");
        }
    }
    for h in [
        ("cookie", "concord_session=abc"),
        ("authorization", "Bearer nope"),
        ("authorization", "Basic YTpi"),
    ] {
        let st = s.status(Method::GET, "/api/v1/version", &[h]).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(s.status(Method::GET, "/healthz", &[]).await, StatusCode::OK);
}

#[tokio::test]
async fn session_contract_over_tls() {
    let s = start(true, Limits::default()).await;
    let (set, cookie) = s.login("user2@pve").await;
    for attr in ["HttpOnly", "SameSite=Strict", "Secure", "Path=/"] {
        assert!(set.split("; ").any(|a| a == attr), "{attr}");
    }
    let r = s
        .req(Method::GET, "/api/v1/session")
        .header("cookie", &cookie)
        .send()
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    let v: Value = r.json().await.expect("json");
    assert_eq!(v, json!({"user": "user2@pve", "role": "admin"}));
    // Two cookies of the name are ambiguous.
    let two = format!("{cookie}; {cookie}");
    let st = s
        .status(Method::GET, "/api/v1/session", &[("cookie", &two)])
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let good = [("cookie", cookie.as_str()), ("x-concord-request", "1")];
    let del = s.status(Method::DELETE, "/api/v1/session", &good).await;
    assert_eq!(del, StatusCode::NO_CONTENT);
    let st = s.status(Method::GET, "/api/v1/session", &good).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn security_headers_are_on_every_response() {
    let s = start(false, Limits::default()).await;
    for (p, host) in [
        ("/healthz", "localhost"),
        ("/nope", "localhost"),
        ("/api/v1/version", "localhost"),
        ("/healthz", "evil.example"),
    ] {
        let r = s
            .req(Method::GET, p)
            .header("host", host)
            .send()
            .await
            .expect("resp");
        let csp = r.headers()["content-security-policy"]
            .to_str()
            .expect("csp");
        assert_eq!(
            csp,
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; \
             frame-ancestors 'none'"
        );
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    }
}

#[tokio::test]
async fn roles_and_csrf() {
    let s = start(false, Limits::default()).await;
    let (set, admin) = s.login("user2@pve").await;
    assert!(!set.contains("Secure"), "plain http cannot use Secure");
    let (_, ro) = s.login("user1@pve").await;
    let token = Users::add_token(&s.users, "bot", Role::Admin).expect("token");
    let ro_token = Users::add_token(&s.users, "watch", Role::ReadOnly).expect("token");
    let same = s.base.clone();
    let t = "/api/v1/test";
    let mark = ("x-concord-request", "1");
    let a = ("cookie", admin.as_str());
    for m in [Method::POST, Method::PUT, Method::DELETE] {
        for (want, headers) in [
            (403, vec![a]),
            (403, vec![a, ("x-concord-request", "0")]),
            (200, vec![a, mark]),
            (200, vec![a, mark, ("origin", same.as_str())]),
            (403, vec![a, mark, ("origin", "http://evil.example")]),
            (403, vec![a, mark, ("origin", "https://evil.example")]),
            (403, vec![a, mark, ("origin", "null")]),
            (403, vec![("cookie", ro.as_str()), mark]),
        ] {
            let st = s.status(m.clone(), t, &headers).await;
            assert_eq!(st.as_u16(), want, "{m} {headers:?}");
        }
        let auth = format!("Bearer {}", *token);
        assert_eq!(
            s.status(m.clone(), t, &[("authorization", &auth)]).await,
            200
        );
        let auth = format!("Bearer {}", *ro_token);
        assert_eq!(s.status(m, t, &[("authorization", &auth)]).await, 403);
    }
    assert_eq!(s.status(Method::GET, t, &[("cookie", &ro)]).await, 200);
    // A bad token is not excused by a good cookie.
    let both = [a, ("authorization", "Bearer nope")];
    assert_eq!(s.status(Method::GET, t, &both).await, 401);
    // A read-only user may end its own session, with the header.
    let c = ("cookie", ro.as_str());
    assert_eq!(s.status(Method::DELETE, "/api/v1/session", &[c]).await, 403);
    assert_eq!(
        s.status(Method::DELETE, "/api/v1/session", &[c, mark])
            .await,
        204
    );
    // Login CSRF.
    let r = s
        .req(Method::POST, "/api/v1/session")
        .header("origin", "http://evil.example")
        .json(&json!({"username": "user2@pve", "password": PASS}))
        .send()
        .await
        .expect("resp");
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn changes_to_the_file_reach_a_running_server() {
    let s = start(false, Limits::default()).await;
    let v = "/api/v1/session";
    let (_, cookie) = s.login("user1@pve").await;
    let token = Users::add_token(&s.users, "bot", Role::Admin).expect("token");
    let auth = format!("Bearer {}", *token);
    assert_eq!(
        s.status(Method::GET, v, &[("authorization", &auth)]).await,
        200
    );
    Users::remove_token(&s.users, "bot").expect("rm");
    assert_eq!(
        s.status(Method::GET, v, &[("authorization", &auth)]).await,
        401
    );
    assert_eq!(s.status(Method::GET, v, &[("cookie", &cookie)]).await, 200);
    Users::remove_user(&s.users, "user1@pve").expect("rm");
    // Added again under the same name and password before the next request: it
    // is still not the login the session was made from.
    Users::add_user(&s.users, "user1@pve", Role::Admin, PASS).expect("add");
    assert_eq!(s.status(Method::GET, v, &[("cookie", &cookie)]).await, 401);
    // A broken file refuses everyone rather than keeping the old users.
    let (_, cookie) = s.login("user1@pve").await;
    let good = std::fs::read_to_string(&s.users).expect("read");
    concord_config::write_private(&s.users, "not toml [").expect("write");
    assert_eq!(s.status(Method::GET, v, &[("cookie", &cookie)]).await, 401);
    concord_config::write_private(&s.users, &good).expect("write");
    let (_, cookie) = s.login("user1@pve").await;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&s.users, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    assert_eq!(s.status(Method::GET, v, &[("cookie", &cookie)]).await, 401);
    std::fs::remove_file(&s.users).expect("rm");
    assert_eq!(s.status(Method::GET, v, &[("cookie", &cookie)]).await, 401);
    assert_eq!(s.status(Method::GET, "/healthz", &[]).await, 200);
    assert_eq!(s.try_login("user1@pve", PASS).await.status(), 401);
}

#[tokio::test]
async fn failed_logins_are_throttled_and_indistinct() {
    let s = start(false, Limits::default()).await;
    let a = s.try_login("user2@pve", "wrong password").await;
    let b = s.try_login("nobody", "wrong password").await;
    assert_eq!(
        (a.status(), b.status()),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(a.text().await.expect("a"), b.text().await.expect("b"));
    // Successes do not count towards the limit.
    for _ in 0..6 {
        s.login("user2@pve").await;
    }
    for _ in 0..3 {
        assert_eq!(s.try_login("nobody", PASS).await.status(), 401);
    }
    let r = s.try_login("user2@pve", PASS).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn bad_login_bodies_are_not_echoed() {
    let s = start(false, Limits::default()).await;
    for body in ["{\"username\":\"hunter2hunter2", "{\"hunter2hunter2\":1}"] {
        let r = s
            .req(Method::POST, "/api/v1/session")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("resp");
        assert!(r.status().is_client_error());
        assert!(!r.text().await.expect("text").contains("hunter2"));
    }
    let big = "x".repeat(100_000);
    assert_eq!(s.try_login("user2@pve", &big).await.status(), 413);
    assert_eq!(
        s.try_login("user2@pve", &"x".repeat(2000)).await.status(),
        401
    );
}

/// Whether the server closes the connection within three seconds.
async fn closes(mut c: TcpStream) -> bool {
    let mut b = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(3), async {
        while !matches!(c.read(&mut b).await, Ok(0) | Err(_)) {}
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn silent_clients_are_cut_off_and_connections_are_limited() {
    let limits = Limits {
        connections: 2,
        handshake: Duration::from_millis(400),
        header: Duration::from_millis(400),
        lifetime: Duration::from_secs(60),
        drain: Duration::from_millis(300),
    };
    for https in [false, true] {
        let s = start(https, limits).await;
        let a = TcpStream::connect(s.addr).await.expect("a");
        let mut b = TcpStream::connect(s.addr).await.expect("b");
        if !https {
            b.write_all(b"GET /healthz HTTP/1.1\r\nHost: loc")
                .await
                .expect("w");
        }
        // Both slots are taken, so this waits for a timeout to free one.
        let t = std::time::Instant::now();
        assert_eq!(s.status(Method::GET, "/healthz", &[]).await, 200);
        assert!(t.elapsed() > Duration::from_millis(200));
        assert!(closes(a).await && closes(b).await);
    }
    // Idle keep-alive, and a connection past its lifetime.
    let s = start(false, limits).await;
    let mut c = TcpStream::connect(s.addr).await.expect("c");
    c.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("w");
    assert!(closes(c).await);
    let lifetime = Duration::from_millis(300);
    let header = Duration::from_secs(60);
    let s = start(
        false,
        Limits {
            lifetime,
            header,
            ..limits
        },
    )
    .await;
    let c = TcpStream::connect(s.addr).await.expect("c");
    assert!(closes(c).await);
}

#[tokio::test]
async fn the_drain_is_bounded() {
    let limits = Limits {
        drain: Duration::from_millis(300),
        ..Limits::default()
    };
    let s = start(true, limits).await;
    let (_, cookie) = s.login("user2@pve").await;
    let slow = s
        .req(Method::GET, "/api/v1/slow")
        .header("cookie", cookie)
        .send();
    let slow = tokio::spawn(slow);
    tokio::time::sleep(Duration::from_millis(200)).await;
    s.stop.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(3), s.done)
        .await
        .expect("bounded")
        .expect("join")
        .expect("serve");
    assert!(slow.await.expect("join").is_err());
}

#[tokio::test]
async fn plain_http_beyond_loopback_is_never_served() {
    let l = TcpListener::bind("0.0.0.0:0").await.expect("bind");
    let (_tx, rx) = watch::channel(false);
    let r = serve(l, Router::new(), None, Limits::default(), rx).await;
    assert!(r.is_err());
}

#[test]
fn certificate_is_generated_once_private_and_never_replaced() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().expect("tmp");
    let first = make_tls(d.path()).fingerprint;
    assert_eq!(first, make_tls(d.path()).fingerprint);
    let f = d.path().join("state").join(tls::SELF_SIGNED);
    let mode = std::fs::metadata(&f).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(tls::setup(&config(d.path(), "192.0.2.10:8010")).is_err());
    assert!(tls::setup(&config(d.path(), "127.0.0.1:8010"))
        .expect("ok")
        .is_none());
    // A configured certificate is used, on loopback too; its key must be private.
    let mut cfg = config(d.path(), "127.0.0.1:8010");
    cfg.tls_cert = Some(f.clone());
    cfg.tls_key = Some(f.clone());
    assert!(tls::setup(&cfg).is_err());
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let t = tls::setup(&cfg).expect("ok").expect("tls");
    assert_eq!(t.fingerprint, first);
}

#[test]
fn managing_users_and_tokens() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().expect("tmp");
    let f = d.path().join("users.toml");
    assert!(Users::load(&f).expect("absent").is_empty());
    assert!(Users::add_user(&f, "a", Role::Admin, "short").is_err());
    assert!(Users::add_user(&f, "bad name", Role::Admin, PASS).is_err());
    Users::add_user(&f, "user1@pve", Role::Admin, PASS).expect("add");
    assert!(Users::add_user(&f, "user1@pve", Role::ReadOnly, PASS).is_err());
    let run = |c: Command| {
        let mut out = Vec::new();
        manage(&c, &f, &mut out).map(|()| String::from_utf8(out).expect("utf8"))
    };
    let add = || {
        run(Command::Token(TokenCommand::Add {
            name: "bot".into(),
            role: Role::ReadOnly,
        }))
    };
    let secret = add().expect("token");
    assert_eq!(secret.trim().len(), "concord_".len() + 64);
    assert!(add().is_err());
    let text = std::fs::read_to_string(&f).expect("read");
    assert!(text.contains("$argon2id$"));
    assert!(!text.contains(secret.trim()) && !text.contains(PASS));
    let mode = std::fs::metadata(&f).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let list = run(Command::User(UserCommand::List)).expect("list");
    assert!(list.contains("user1@pve  admin") && list.contains("bot  readonly"));
    assert!(!list.contains("argon2"));
    let rm = || {
        run(Command::User(UserCommand::Remove {
            name: "user1@pve".into(),
        }))
    };
    rm().expect("rm");
    assert!(rm().is_err());
    let rm = || run(Command::Token(TokenCommand::Remove { name: "bot".into() }));
    rm().expect("rm");
    assert!(rm().is_err());
    // A hash with other parameters is refused, as is an unknown field.
    let cheap = text.replace("m=19456", "m=8");
    assert_ne!(cheap, text);
    concord_config::write_private(&f, &cheap).expect("w");
    assert!(Users::load(&f).is_err());
    concord_config::write_private(&f, "typo = 1").expect("w");
    assert!(Users::load(&f).is_err());
    // Two writers at once lose nothing.
    concord_config::write_private(&f, "").expect("w");
    std::thread::scope(|s| {
        for i in 0..8 {
            let f = &f;
            s.spawn(move || Users::add_token(f, &format!("t{i}"), Role::ReadOnly).map(drop));
        }
    });
    assert_eq!(Users::load(&f).expect("load").tokens.len(), 8);
}

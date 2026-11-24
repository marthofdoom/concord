use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use concord_inventory::{InventoryConfig, Poller};
use concord_server::{guard_host, router, AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

fn app(listen: &str) -> Router {
    let (_, inventory) = Poller::new(Vec::new(), InventoryConfig::default());
    guard_host(
        router(AppState { inventory }),
        listen.parse::<SocketAddr>().expect("addr"),
    )
}

async fn status(app: &Router, uri: &str, hosts: &[&str]) -> StatusCode {
    let mut req = Request::get(uri);
    for h in hosts {
        req = req.header("host", *h);
    }
    let req = req.body(Body::empty()).expect("req");
    app.clone().oneshot(req).await.expect("resp").status()
}

#[tokio::test]
async fn loopback_names_are_served() {
    // Built rather than written out: the leak scan flags IPv6 literals.
    let v6 = std::net::Ipv6Addr::LOCALHOST;
    let mapped = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    let (v6_host, v6_port) = (format!("[{v6}]"), format!("[{v6}]:8010"));
    let mapped = format!("[{mapped}]:8010");
    for listen in ["127.0.0.1:8010", &v6_port, &mapped] {
        let a = app(listen);
        for h in [
            "localhost",
            "LocalHost:8010",
            "127.0.0.1",
            "127.0.0.1:8010",
            "127.8.9.1:1",
            &v6_host,
            &v6_port,
        ] {
            assert_eq!(status(&a, "/healthz", &[h]).await, StatusCode::OK, "{h}");
        }
    }
}

#[tokio::test]
async fn other_names_are_misdirected() {
    let a = app("127.0.0.1:8010");
    for h in [
        "evil.example",
        "evil.example:8010",
        "localhost.evil.example",
        "127.0.0.1.evil.example",
        "localhost@evil.example",
        "evil.example@localhost",
        "localhost.",
        "192.0.2.1",
        "0.0.0.0",
        "2130706433",
        "[2001:db8::1]:8010",
        "[::]",
        "[localhost]",
        "",
        "localhost, evil.example",
    ] {
        for path in ["/healthz", "/api/v1/estate", "/no-such-route"] {
            assert_eq!(
                status(&a, path, &[h]).await,
                StatusCode::MISDIRECTED_REQUEST,
                "{h} {path}"
            );
        }
    }
}

#[tokio::test]
async fn missing_repeated_and_absolute_form() {
    let a = app("127.0.0.1:8010");
    let no = StatusCode::MISDIRECTED_REQUEST;
    assert_eq!(status(&a, "/healthz", &[]).await, no);
    let two = ["localhost", "evil.example"];
    assert_eq!(status(&a, "/healthz", &two).await, no);
    let good = "http://127.0.0.1:8010/healthz";
    let bad = "http://evil.example/healthz";
    assert_eq!(status(&a, good, &[]).await, StatusCode::OK);
    assert_eq!(status(&a, good, &["localhost"]).await, StatusCode::OK);
    assert_eq!(status(&a, good, &["evil.example"]).await, no);
    assert_eq!(status(&a, bad, &["localhost"]).await, no);
    assert_eq!(status(&a, bad, &[]).await, no);
}

#[tokio::test]
async fn beyond_loopback_any_name_is_served() {
    let a = app("0.0.0.0:8010");
    assert_eq!(
        status(&a, "/healthz", &["concord.example"]).await,
        StatusCode::OK
    );
}

/// Over a socket, because hyper decides what becomes of Host and the target.
#[tokio::test]
async fn over_a_real_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let a = guard_host(app("0.0.0.0:1"), addr);
    tokio::spawn(async move { axum::serve(listener, a).await });

    for (head, want) in [
        (format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\n"), "200"),
        (
            "GET /healthz HTTP/1.1\r\nHost: evil.example\r\n".into(),
            "421",
        ),
        ("GET /healthz HTTP/1.1\r\n".into(), "421"),
        ("GET /healthz HTTP/1.0\r\n".into(), "421"),
        (
            "GET http://evil.example/healthz HTTP/1.1\r\nHost: localhost\r\n".into(),
            "421",
        ),
        (
            "GET http://localhost/healthz HTTP/1.1\r\nHost: evil.example\r\n".into(),
            "421",
        ),
        (
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n".into(),
            "421",
        ),
    ] {
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let msg = format!("{head}Connection: close\r\n\r\n");
        s.write_all(msg.as_bytes()).await.expect("write");
        let mut out = String::new();
        s.read_to_string(&mut out).await.expect("read");
        let got = out.split(' ').nth(1);
        assert_eq!(got, Some(want), "{head:?} -> {out}");
    }
}

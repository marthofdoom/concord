//! Refuses requests addressed to a name that is not this machine's loopback.
//!
//! Plain HTTP and unauthenticated routes are reachable on loopback because only
//! this machine is there, and DNS rebinding defeats that: a web page open on this machine can point its own name at 127.0.0.1 and
//! read the replies as same-origin. The browser still sends that name as Host,
//! which is what gives it away.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::Request;
use axum::http::header::HOST;
use axum::http::uri::Authority;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;

/// Wraps `app` for serving on `listen`. Beyond loopback it changes nothing:
/// which names are legitimate there is the operator's to know.
pub fn guard_host(app: Router, listen: SocketAddr) -> Router {
    if listen.ip().to_canonical().is_loopback() {
        crate::secure_headers(app.layer(middleware::from_fn(check)))
    } else {
        app
    }
}

async fn check(req: Request, next: Next) -> Response {
    if addressed_to_loopback(&req) {
        next.run(req).await
    } else {
        crate::error(
            StatusCode::MISDIRECTED_REQUEST,
            "this server listens on loopback and answers only to a loopback Host",
        )
    }
}

/// Every place a request can name its host must agree: an absolute-form target
/// (or HTTP/2 `:authority`) with a good name does not excuse a bad Host header,
/// nor the reverse. At least one has to be present.
fn addressed_to_loopback(req: &Request) -> bool {
    let mut headers = req.headers().get_all(HOST).iter();
    let header = headers.next();
    if headers.next().is_some() {
        return false;
    }
    let header_ok = header.map(|v| {
        v.to_str()
            .ok()
            .and_then(|s| s.parse::<Authority>().ok())
            .is_some_and(|a| is_loopback(&a))
    });
    let target_ok = req.uri().authority().map(is_loopback);
    match (header_ok, target_ok) {
        (None, None) => false,
        (h, t) => h.unwrap_or(true) && t.unwrap_or(true),
    }
}

/// The port is not compared: a forwarded port (`ssh -L`) legitimately differs,
/// and rebinding cannot produce a loopback name.
fn is_loopback(a: &Authority) -> bool {
    if a.as_str().contains('@') {
        return false;
    }
    let host = a.host();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback()),
        None => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    }
}

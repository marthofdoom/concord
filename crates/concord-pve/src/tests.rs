//! Anything shaped like a PVE response is loaded from the captured fixture sets
//! (`tests/fixtures`). The `GRAMMAR_*` literals are hand-written on
//! purpose: they probe the UPID grammar at its edges, which no real task hits.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::http::parse_envelope;
use crate::*;

const CANARY: &str = "5ec7e75e-cafe-4bad-8eed-c0ffee000001";

const GRAMMAR_UPID: &str = "UPID:pve1:00002F9D:000DC5EA:57500527:vzcreate:602:root@pam:";
const GRAMMAR_UPID_TOKEN: &str =
    "UPID:pve-2:0000ABCD:1A2B3C4D5:6650A1B2:aptupdate::root@pam!concord:";

/// The captured stopped-OK task status from the newest committed set that has
/// one: (node, upid, status body).
fn captured_task() -> (String, String, Value) {
    let set = FixtureSet::committed("9.2.21").unwrap();
    for (path, status, body) in &set.endpoints {
        if *status == 200
            && path.contains("/tasks/UPID")
            && path.ends_with("/status")
            && body["exitstatus"] == "OK"
        {
            let node = body["node"].as_str().unwrap().to_string();
            let upid = body["upid"].as_str().unwrap().to_string();
            return (node, upid, body.clone());
        }
    }
    panic!("no stopped task status in the 9.2.21 fixtures");
}

fn node() -> String {
    captured_task().0
}

fn upid() -> String {
    captured_task().1
}

fn token() -> ApiToken {
    ApiToken::new("root@pam", "concord", Secret::new(CANARY))
}

// ---- fingerprint ----

#[test]
fn fingerprint_parses_pve_format_and_variants() {
    let colon = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
    let a: Fingerprint = colon.parse().unwrap();
    let b: Fingerprint = colon.to_lowercase().parse().unwrap();
    let c: Fingerprint = colon.replace(':', "").parse().unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a.to_string(), colon);
}

#[test]
fn fingerprint_rejects_garbage() {
    for bad in [
        "",
        "AA:BB",
        "zz".repeat(32).as_str(),
        &"AA:".repeat(33),
        &"AB".repeat(31),
        &"AB".repeat(33),
        &format!("{}:ZZ", "AA:".repeat(31).trim_end_matches(':')),
        &format!("A:{}", "AA:".repeat(31).trim_end_matches(':')),
    ] {
        assert!(bad.parse::<Fingerprint>().is_err(), "accepted {bad:?}");
    }
}

// ---- envelope ----

#[test]
fn envelope_unwraps_data() {
    let real = FixtureSet::committed("9.2.21")
        .unwrap()
        .data("/version")
        .unwrap()
        .clone();
    let body = json!({ "data": real }).to_string();
    let v = parse_envelope(200, None, body.as_bytes()).unwrap();
    assert_eq!(v, real);
    // A void method answers with an explicit null.
    assert_eq!(
        parse_envelope(200, None, br#"{"data":null}"#).unwrap(),
        Value::Null
    );
}

#[test]
fn envelope_error_carries_message_and_errors() {
    let body = br#"{"data":null,"message":"Parameter verification failed.\n","errors":{"vmid":"value must be >= 100"}}"#;
    match parse_envelope(400, None, body) {
        Err(PveError::Http {
            status,
            message,
            errors,
        }) => {
            assert_eq!(status, 400);
            assert!(message.starts_with("Parameter verification failed"));
            assert_eq!(errors, Some(json!({"vmid": "value must be >= 100"})));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn envelope_non_json_error_body_is_the_message() {
    match parse_envelope(500, None, b"no such file\n") {
        Err(PveError::Http {
            status: 500,
            message,
            errors: None,
        }) => assert_eq!(message, "no such file"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn envelope_2xx_without_data_is_decode_error() {
    assert!(matches!(
        parse_envelope(200, None, b"{}"),
        Err(PveError::Decode(_))
    ));
    assert!(matches!(
        parse_envelope(200, None, b"not json"),
        Err(PveError::Decode(_))
    ));
    assert!(matches!(
        parse_envelope(200, None, b"[1]"),
        Err(PveError::Decode(_))
    ));
}

#[test]
fn envelope_failure_inside_200_body_is_an_error() {
    let body = br#"{"success":0,"message":"boom","data":null}"#;
    assert!(matches!(
        parse_envelope(200, None, body),
        Err(PveError::Http { status: 200, .. })
    ));
    let ok = br#"{"success":1,"data":[]}"#;
    assert_eq!(parse_envelope(200, None, ok).unwrap(), json!([]));
}

// ---- paths and upids ----

#[test]
fn upid_is_percent_encoded_in_paths() {
    let p = api_path(&["nodes", "pve1", "tasks", GRAMMAR_UPID, "status"]).unwrap();
    assert_eq!(
        p,
        "/nodes/pve1/tasks/UPID%3Apve1%3A00002F9D%3A000DC5EA%3A57500527%3Avzcreate%3A602%3Aroot%40pam%3A/status"
    );
    // A segment can never add path components.
    assert_eq!(api_path(&["a/../b"]).unwrap(), "/a%2F..%2Fb");
}

#[test]
fn upid_round_trips() {
    for s in [GRAMMAR_UPID, GRAMMAR_UPID_TOKEN] {
        let u: Upid = s.parse().unwrap();
        assert_eq!(u.to_string(), s);
    }
    let u: Upid = GRAMMAR_UPID.parse().unwrap();
    assert_eq!(u.node, "pve1");
    assert_eq!(u.pid, 0x2F9D);
    assert_eq!(u.task_type, "vzcreate");
    assert_eq!(u.id, "602");
    assert_eq!(u.user, "root@pam");
    let t: Upid = GRAMMAR_UPID_TOKEN.parse().unwrap();
    assert_eq!(t.id, "");
    assert_eq!(t.user, "root@pam!concord");
    assert_eq!(t.pstart, 0x1A2B3C4D5);
}

#[test]
fn upid_rejects_malformed() {
    for bad in [
        "",
        "UPID:pve1",
        "UPID:pve1:1:2:3:t:i:u:",
        "UPID:-x:00002F9D:000DC5EA:57500527:t:i:u:",
        "UPID:pve1:00002F9D:000DC5EA:57500527:t:i:u",
        // pve-common's decode regex excludes `/` from type, id and user.
        "UPID:pve1:00002F9D:000DC5EA:57500527:t:a/b:u:",
    ] {
        assert!(bad.parse::<Upid>().is_err(), "accepted {bad:?}");
    }
}

// ---- task poller ----

fn status_path() -> String {
    api_path(&["nodes", &node(), "tasks", &upid(), "status"]).unwrap()
}

/// The real stopped status with `exitstatus` swapped, for outcomes the host
/// had no example of; keeps every other field exactly as PVE sent it.
fn stopped_with(exit: &str) -> Value {
    let mut b = captured_task().2;
    b["exitstatus"] = json!(exit);
    b
}

/// The real status as it reads while the task is still going: `status` flips
/// and `exitstatus` is absent (derived, not observed: a running task is gone
/// by the time a capture could read it).
fn running() -> Value {
    let mut b = captured_task().2;
    b["status"] = json!("running");
    b.as_object_mut().unwrap().remove("exitstatus");
    b
}

fn mock_task(exit: Option<&str>, running_polls: usize) -> MockPve {
    let p = status_path();
    let mut m = MockPve::new();
    for _ in 0..running_polls {
        m = m.on(Method::Get, &p, running());
    }
    match exit {
        Some(e) => m.on(Method::Get, &p, stopped_with(e)),
        None => m,
    }
}

async fn wait(m: &MockPve, timeout_s: u64) -> TaskOutcome {
    wait_for_task(
        m,
        &node(),
        &upid(),
        Duration::from_secs(2),
        Duration::from_secs(timeout_s),
    )
    .await
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn poller_reports_each_outcome_distinctly() {
    assert_eq!(wait(&mock_task(Some("OK"), 2), 60).await, TaskOutcome::Ok);
    assert_eq!(
        wait(&mock_task(Some("WARNINGS: 3"), 1), 60).await,
        TaskOutcome::Warnings(3)
    );
    assert_eq!(
        wait(&mock_task(Some("command 'x' failed: exit code 1"), 0), 60).await,
        TaskOutcome::Failed("command 'x' failed: exit code 1".into())
    );
    // Never stops: the last "running" repeats.
    let m = mock_task(None, 1);
    assert_eq!(wait(&m, 10).await, TaskOutcome::TimedOut);
    assert!(m.calls().len() >= 2);
}

#[tokio::test(start_paused = true)]
async fn poller_propagates_api_errors_and_maps_to_pve_errors() {
    let m = MockPve::new();
    assert!(matches!(
        wait_for_task(
            &m,
            &node(),
            &upid(),
            Duration::from_secs(1),
            Duration::from_secs(5)
        )
        .await,
        Err(PveError::Mock(_))
    ));
    let w = Duration::from_secs(5);
    assert!(TaskOutcome::Ok.into_result("u", w).is_ok());
    assert!(matches!(
        TaskOutcome::Failed("x".into()).into_result("u", w),
        Err(PveError::TaskFailed { .. })
    ));
    assert!(matches!(
        TaskOutcome::TimedOut.into_result("u", w),
        Err(PveError::TaskTimeout { .. })
    ));
}

#[tokio::test]
async fn mock_names_unregistered_calls_and_records() {
    let real = FixtureSet::committed("9.2.21").unwrap();
    let m = MockPve::new().on(
        Method::Get,
        "/version",
        real.data("/version").unwrap().clone(),
    );
    let v = m.version().await.unwrap();
    assert_eq!(v.version, "9.2.21");
    let err = m
        .request(Method::Post, "/nodes", &[("a", "b".into())])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("POST /nodes"));
    assert_eq!(m.calls().len(), 2);
    assert_eq!(
        m.calls()[1].params,
        vec![("a".to_string(), "b".to_string())]
    );
    let dynapi: Arc<dyn PveApi> = Arc::new(m);
    assert!(dynapi.nodes().await.is_err());
}

// ---- redaction ----

#[test]
fn secret_never_appears_in_debug_or_display() {
    let t = token();
    for s in [
        format!("{:?}", t.secret),
        format!("{}", t.secret),
        format!("{t:?}"),
        format!("{t:#?}"),
    ] {
        assert!(!s.contains(CANARY), "leaked in {s}");
    }
    let fp: Fingerprint = "00".repeat(32).parse().unwrap();
    let client = HttpPveClient::new(
        "https://127.0.0.1:8006".parse().unwrap(),
        t,
        fp,
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(!format!("{client:?}").contains(CANARY));

    let variants = [
        PveError::FingerprintMismatch {
            expected: "a".into(),
            actual: "b".into(),
        },
        PveError::Connect("refused".into()),
        PveError::Timeout,
        PveError::Transport("reset".into()),
        PveError::Http {
            status: 401,
            message: "no".into(),
            errors: Some(json!({"k":"v"})),
        },
        PveError::Decode("bad".into()),
        PveError::TaskFailed {
            upid: "u".into(),
            exitstatus: "e".into(),
        },
        PveError::TaskTimeout {
            upid: "u".into(),
            waited: Duration::from_secs(1),
        },
        PveError::InvalidRequest("x".into()),
        PveError::Mock("m".into()),
    ];
    for e in variants {
        assert!(!format!("{e}").contains(CANARY));
        assert!(!format!("{e:?}").contains(CANARY));
        let core: concord_core::Error = e.into();
        assert!(!format!("{core}").contains(CANARY));
    }
}

#[test]
fn bad_token_errors_do_not_echo_the_secret() {
    let t = ApiToken::new("root@pam", "concord", Secret::new(format!("{CANARY}\n")));
    let fp: Fingerprint = "00".repeat(32).parse().unwrap();
    let err = HttpPveClient::new(
        "https://h:8006".parse().unwrap(),
        t,
        fp,
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(!err.to_string().contains(CANARY));
    assert!(!format!("{err:?}").contains(CANARY));
}

#[test]
fn token_secret_must_be_uuid_shaped() {
    let header =
        |secret: String| ApiToken::new("root@pam", "concord", Secret::new(secret)).header_value();
    for good in [
        CANARY.to_string(),
        CANARY.to_uppercase(),
        "00000000-0000-0000-0000-000000000000".to_string(),
    ] {
        assert!(header(good).is_ok());
    }
    // Every bad secret embeds the canary (or a recognisable piece of it), so
    // an error that echoed the value would be caught below.
    let mut bad = vec![
        String::new(),
        "s3cr3t-canary-1234".to_string(),
        format!("{CANARY}0"),
        CANARY[..35].to_string(),
        CANARY.replace('-', ""),
        CANARY.replacen('-', "_", 1),
        format!("{}x", &CANARY[..35]),
        // PVE would split at the last '=', cut at ';' and unescape '%41'.
        format!("{}=", &CANARY[..35]),
        format!("{};", &CANARY[..35]),
        format!("{}%41", &CANARY[..33]),
        format!("{} ", &CANARY[..35]),
    ];
    // Same length, a delimiter in place of a hex digit.
    for c in ['=', ';', '%'] {
        bad.push(format!("{c}{}", &CANARY[1..]));
    }
    for secret in bad {
        let err = header(secret.clone()).unwrap_err();
        assert!(
            matches!(err, PveError::InvalidRequest(_)),
            "accepted secret {secret:?}"
        );
        for s in [format!("{err}"), format!("{err:?}")] {
            assert!(!s.contains("c0ffee000001"), "leaked in {s}");
            assert!(!s.contains("s3cr3t"), "leaked in {s}");
            assert!(s.contains("secret"), "error does not name the field: {s}");
        }
    }
}

#[test]
fn rejects_non_https_and_non_origin_urls() {
    let fp: Fingerprint = "00".repeat(32).parse().unwrap();
    for u in [
        "http://h:8006",
        "https://h:8006/prefix",
        "https://u:p@h:8006",
    ] {
        assert!(
            HttpPveClient::new(u.parse().unwrap(), token(), fp, Duration::from_secs(1)).is_err(),
            "{u}"
        );
    }
}

// ---- TLS pinning against a live local server ----

const VERSION_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 62\r\nConnection: close\r\n\r\n{\"data\":{\"version\":\"9.1\",\"release\":\"9.1\",\"repoid\":\"deadbeef\"}}";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS server presenting a fresh self-signed cert and answering every
/// request with `response`. With `foreign_key`, the handshake is signed by a
/// different key than the one in the presented cert.
async fn spawn_server(
    response: &'static str,
    foreign_key: bool,
    versions: &'static [&'static rustls::SupportedProtocolVersion],
) -> (u16, Fingerprint) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let fp = Fingerprint::of_der(der.as_ref());
    let key_pair = if foreign_key {
        rcgen::KeyPair::generate().unwrap()
    } else {
        ck.key_pair
    };
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    // `with_single_cert` refuses a cert/key pair that does not match, so the
    // foreign-key case builds the `CertifiedKey` directly, which does not.
    let signing_key = provider()
        .key_provider
        .load_private_key(key.into())
        .unwrap();
    let certified = rustls::sign::CertifiedKey::new(vec![der], signing_key);
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                serve_one(&mut tls, response).await;
            });
        }
    });
    (port, fp)
}

async fn serve_one<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    response: &str,
) {
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    let _ = s.write_all(response.as_bytes()).await;
    let _ = s.shutdown().await;
}

async fn spawn_tls_server() -> (u16, Fingerprint) {
    spawn_server(VERSION_OK, false, rustls::DEFAULT_VERSIONS).await
}

fn client_for(port: u16, pin: Fingerprint) -> HttpPveClient {
    let url: reqwest::Url = format!("https://127.0.0.1:{port}").parse().unwrap();
    HttpPveClient::new(url, token(), pin, Duration::from_secs(5)).unwrap()
}

#[tokio::test]
async fn right_pin_connects_and_wrong_pin_is_rejected() {
    let (port, fp) = spawn_tls_server().await;
    let url: reqwest::Url = format!("https://127.0.0.1:{port}").parse().unwrap();

    let good = HttpPveClient::new(url.clone(), token(), fp, Duration::from_secs(5)).unwrap();
    let v = good.version().await.unwrap();
    assert_eq!(v.repoid, "deadbeef");

    let wrong: Fingerprint = "AB".repeat(32).parse().unwrap();
    let bad = HttpPveClient::new(url, token(), wrong, Duration::from_secs(5)).unwrap();
    match bad.version().await {
        Err(PveError::FingerprintMismatch { expected, actual }) => {
            assert_eq!(expected, wrong.to_string());
            assert_eq!(actual, fp.to_string());
        }
        other => panic!("expected fingerprint mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn handshake_signed_by_another_key_is_rejected_despite_the_pin() {
    // Covers both signature paths: TLS 1.3 CertificateVerify and TLS 1.2
    // ServerKeyExchange.
    static TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    for versions in [TLS13, TLS12] {
        let (port, fp) = spawn_server(VERSION_OK, true, versions).await;
        match client_for(port, fp).version().await {
            Err(PveError::Connect(_)) | Err(PveError::Transport(_)) => {}
            other => panic!("expected a handshake failure, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_failures_keep_their_own_variants() {
    // One client has one base URL, so the "unrelated failure" is a connection
    // to the same port that the server drops before the TLS handshake, rather
    // than a closed port. The first connection gets a cert that does not match
    // the pin. The server holds both until both are accepted and then fails
    // them together, so their errors are mapped concurrently.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let real = Fingerprint::of_der(der.as_ref());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key.into())
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (a, _) = listener.accept().await.unwrap();
        let _ = first_tx.send(());
        let (b, _) = listener.accept().await.unwrap();
        drop(b);
        let _ = acceptor.accept(a).await;
    });

    let pin: Fingerprint = "AB".repeat(32).parse().unwrap();
    let client = Arc::new(client_for(port, pin));
    let c = client.clone();
    let mismatched = tokio::spawn(async move { c.version().await });
    first_rx.await.unwrap();
    let c = client.clone();
    let dropped = tokio::spawn(async move { c.version().await });

    match mismatched.await.unwrap() {
        Err(PveError::FingerprintMismatch { expected, actual }) => {
            assert_eq!(expected, pin.to_string());
            assert_eq!(actual, real.to_string());
        }
        other => panic!("expected fingerprint mismatch, got {other:?}"),
    }
    match dropped.await.unwrap() {
        Err(PveError::Connect(_)) | Err(PveError::Transport(_)) => {}
        other => panic!("expected a connection failure, got {other:?}"),
    }
}

// ---- error text ----

#[test]
fn empty_error_body_falls_back_to_reason_phrase() {
    // pveproxy's 401: empty body, text only in the reason phrase (observed).
    match parse_envelope(401, Some("No ticket"), b"") {
        Err(PveError::Http {
            status: 401,
            message,
            errors: None,
        }) => assert_eq!(message, "No ticket"),
        other => panic!("unexpected {other:?}"),
    }
    // A JSON body without `message` also uses the phrase.
    match parse_envelope(403, Some("Permission check failed"), br#"{"data":null}"#) {
        Err(PveError::Http { message, .. }) => assert_eq!(message, "Permission check failed"),
        other => panic!("unexpected {other:?}"),
    }
    // A body message still wins over the phrase.
    match parse_envelope(500, Some("Internal Server Error"), b"boom") {
        Err(PveError::Http { message, .. }) => assert_eq!(message, "boom"),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn live_401_reports_custom_then_canonical_reason() {
    for (response, want) in [
        (
            "HTTP/1.1 401 No ticket\r\nConnection: close\r\n\r\n",
            "No ticket",
        ),
        (
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "Unauthorized",
        ),
    ] {
        let (port, fp) = spawn_server(response, false, rustls::DEFAULT_VERSIONS).await;
        match client_for(port, fp).version().await {
            Err(PveError::Http {
                status: 401,
                message,
                ..
            }) => assert_eq!(message, want),
            other => panic!("unexpected {other:?}"),
        }
    }
}

// ---- path validation ----

#[test]
fn api_path_rejects_dot_and_empty_segments() {
    for bad in ["", ".", "..", "%2e", "%2E", "%2e%2E", ".%2e", "%2E."] {
        assert!(
            matches!(
                api_path(&["nodes", bad, "tasks"]),
                Err(PveError::InvalidRequest(_))
            ),
            "accepted {bad:?}"
        );
    }
    assert_eq!(api_path(&["a.b", "..."]).unwrap(), "/a.b/...");
}

#[tokio::test]
async fn request_rejects_paths_the_url_parser_would_rewrite() {
    let fp: Fingerprint = "00".repeat(32).parse().unwrap();
    // Nothing listens on port 1; validation must refuse before connecting.
    let c = client_for(1, fp);
    for bad in [
        "nodes",
        "/",
        "/nodes/../access",
        "/nodes/./x",
        "/nodes/%2e%2E/access",
        "/nodes/.%2e/access",
        "/nodes//x",
        "/nodes/",
        "/nodes?x=1",
        "/nodes#x",
        "/nodes\\..\\access",
        // The URL parser deletes tab, LF and CR, leaving `..`.
        "/nodes/.\t./access",
        "/nodes/.\n./access",
        "/nodes/.\r./access",
        "/nodes/\t/access",
        "/nodes/\0x",
        "/nodes/\x1fx",
        "/nodes/\x7fx",
        "/nodes/\u{e9}",
        "/nodes/\u{ff0e}\u{ff0e}/access",
    ] {
        assert!(
            matches!(
                c.request(Method::Get, bad, &[]).await,
                Err(PveError::InvalidRequest(_))
            ),
            "accepted {bad:?}"
        );
    }
}

// ---- poller limits ----

#[tokio::test(start_paused = true)]
async fn poller_accepts_unbounded_timeout() {
    let m = mock_task(Some("OK"), 2);
    let out = wait_for_task(&m, &node(), &upid(), Duration::from_secs(1), Duration::MAX)
        .await
        .unwrap();
    assert_eq!(out, TaskOutcome::Ok);
}

#[tokio::test(start_paused = true)]
async fn poller_floors_a_zero_interval() {
    let m = mock_task(Some("OK"), 5);
    let start = tokio::time::Instant::now();
    let out = wait_for_task(
        &m,
        &node(),
        &upid(),
        Duration::ZERO,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(out, TaskOutcome::Ok);
    assert_eq!(m.calls().len(), 6);
    assert_eq!(start.elapsed(), MIN_POLL_INTERVAL * 5);

    // Never stops: polls are bounded by the floor, not spun.
    let m = mock_task(None, 1);
    let out = wait_for_task(&m, &node(), &upid(), Duration::ZERO, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(out, TaskOutcome::TimedOut);
    assert!(m.calls().len() <= 11, "{} polls", m.calls().len());
}

#[tokio::test(start_paused = true)]
async fn warnings_count_is_digits_only_and_saturates() {
    for (exit, want) in [
        ("WARNINGS: 0", TaskOutcome::Warnings(0)),
        ("WARNINGS: 99999999999", TaskOutcome::Warnings(u32::MAX)),
        ("WARNINGS: +5", TaskOutcome::Failed("WARNINGS: +5".into())),
        ("WARNINGS: ", TaskOutcome::Failed("WARNINGS: ".into())),
        ("WARNINGS: 5 ", TaskOutcome::Failed("WARNINGS: 5 ".into())),
    ] {
        assert_eq!(wait(&mock_task(Some(exit), 0), 60).await, want, "{exit:?}");
    }
}

// ---- token grammar ----

#[test]
fn token_user_and_id_follow_pve_grammar() {
    let header = |user: &str, id: &str| ApiToken::new(user, id, Secret::new(CANARY)).header_value();
    for user in [
        "root@pam",
        "a@pve",
        "first.last@my-realm_1",
        // The realm cannot contain `@`, so PVE reads this as user `a@b`.
        "a@b@pve",
    ] {
        assert!(header(user, "concord").is_ok(), "rejected user {user:?}");
    }
    for user in [
        "root",
        "@pam",
        "root@p",
        "root@1am",
        "root@pa!m",
        "ro!ot@pam",
        "ro=ot@pam",
        "ro ot@pam",
        "ro:ot@pam",
        "ro/ot@pam",
        "ro%ot@pam",
        "ro%41ot@pam",
        "ro;ot@pam",
        &format!("{}@pam", "a".repeat(61)),
    ] {
        assert!(
            matches!(header(user, "concord"), Err(PveError::InvalidRequest(_))),
            "accepted user {user:?}"
        );
    }
    for id in ["concord", "c.d-e_f", "ab"] {
        assert!(header("root@pam", id).is_ok(), "rejected token id {id:?}");
    }
    for id in ["", "a", "1abc", "_a", "a=b", "a!b", "a b", "a:b"] {
        assert!(
            matches!(header("root@pam", id), Err(PveError::InvalidRequest(_))),
            "accepted token id {id:?}"
        );
    }
}

// ---- mock ----

#[tokio::test]
async fn mock_repeats_an_error_faithfully() {
    let m = MockPve::new().on_err(
        Method::Get,
        "/version",
        PveError::Http {
            status: 403,
            message: "Permission check failed".into(),
            errors: None,
        },
    );
    for _ in 0..2 {
        match m.version().await {
            Err(PveError::Http {
                status: 403,
                message,
                errors: None,
            }) => assert_eq!(message, "Permission check failed"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

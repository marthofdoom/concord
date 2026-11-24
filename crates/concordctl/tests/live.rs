use std::sync::Arc;

use clap::Parser;
use concord_inventory::{InventoryConfig, Poller};
use concord_pve::{FixtureSet, PveApi};
use concord_server::serve::{serve, Limits};
use concord_server::users::{Role, Users};
use concord_server::{router, tls, AppState, Auth, AuthConfig};
use concordctl::{run, Cli};

struct Server {
    url: String,
    dir: tempfile::TempDir,
    pin: Option<String>,
    _stop: tokio::sync::watch::Sender<bool>,
}

/// Starts the real server on an ephemeral port, one cycle already published.
async fn start(https: bool) -> Server {
    let dir = tempfile::tempdir().expect("tmp");
    let users = dir.path().join("users.toml");
    let secret = Users::add_token(&users, "ctl", Role::ReadOnly).expect("token");
    concord_config::write_private(&dir.path().join("token"), &format!("{}\n", *secret))
        .expect("write");
    let set = FixtureSet::committed("9.2.21").expect("fixture");
    let client: Arc<dyn PveApi> = Arc::new(set.mock());
    let (mut poller, inventory) =
        Poller::new(vec![("h1".into(), client)], InventoryConfig::default());
    poller.run_cycle().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let tls = https.then(|| {
        // A non-loopback listen address is what makes it generate one.
        let text = include_str!("../../../concord.example.toml")
            .replace("127.0.0.1:8010", "192.0.2.10:8010");
        let mut cfg = concord_config::Config::parse(&text).expect("cfg");
        cfg.state_dir = dir.path().join("state");
        tls::setup(&cfg).expect("tls").expect("https")
    });
    let pin = tls.as_ref().map(|t| t.fingerprint.to_string());
    let auth = Auth::new(AuthConfig::new(users, https)).expect("auth");
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let app = router(AppState { inventory }, auth);
        let _ = serve(listener, app, tls.as_ref(), Limits::default(), rx).await;
    });
    let scheme = if https { "https" } else { "http" };
    Server {
        url: format!("{scheme}://{addr}"),
        dir,
        pin,
        _stop: stop,
    }
}

async fn ctl(s: &Server, args: &[&str]) -> (Result<(), concordctl::CtlError>, String) {
    let token = s.dir.path().join("token");
    let mut argv = vec!["--token-file", token.to_str().expect("utf8")];
    if let Some(p) = &s.pin {
        argv.extend(["--fingerprint", p.as_str()]);
    }
    argv.extend_from_slice(args);
    raw(&s.url, &argv).await
}

async fn raw(server: &str, args: &[&str]) -> (Result<(), concordctl::CtlError>, String) {
    let mut argv = vec!["concordctl", "--server", server];
    argv.extend_from_slice(args);
    let cli = Cli::parse_from(argv);
    let mut out = Vec::new();
    let r = run(&cli, &mut out).await;
    (r, String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn https_is_pinned_and_a_wrong_pin_is_refused() {
    let s = start(true).await;
    let (r, out) = ctl(&s, &["hosts"]).await;
    assert!(r.is_ok(), "{r:?}");
    assert!(out.contains("h1"));
    let wrong = "00".repeat(32);
    let (r, _) = raw(&s.url, &["--fingerprint", &wrong, "hosts"]).await;
    let e = r.expect_err("pin").to_string();
    assert!(e.contains("PinMismatch"), "{e}");
    let (r, _) = raw(&s.url, &["hosts"]).await;
    assert!(matches!(r, Err(concordctl::CtlError::Config(_))));
}

#[tokio::test]
async fn plain_http_beyond_loopback_is_refused_before_connecting() {
    for url in [
        "http://192.0.2.10:8010",
        "http://localhost.example:8010",
        "http://127.0.0.1@192.0.2.10:8010",
        "ftp://127.0.0.1",
    ] {
        let (r, _) = raw(url, &["hosts"]).await;
        assert!(matches!(r, Err(concordctl::CtlError::Config(_))), "{url}");
    }
}

#[tokio::test]
async fn the_token_is_needed_and_its_file_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let s = start(false).await;
    let (r, _) = raw(&s.url, &["version"]).await;
    assert!(matches!(
        r,
        Err(concordctl::CtlError::Server { status: 401, .. })
    ));
    let f = s.dir.path().join("token");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let (r, _) = ctl(&s, &["version"]).await;
    assert!(matches!(r, Err(concordctl::CtlError::Config(_))));
}

#[tokio::test]
async fn json_output_is_the_api_body() {
    let s = start(false).await;
    let (r, out) = ctl(&s, &["--json", "guests", "--kind", "lxc"]).await;
    assert!(r.is_ok());
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    assert_eq!(v["guests"].as_array().map(Vec::len), Some(3));
    let (r, out) = ctl(&s, &["--json", "estate"]).await;
    assert!(r.is_ok());
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    assert_eq!(v["cycle"], 1);
}

#[tokio::test]
async fn human_tables() {
    let s = start(false).await;
    let (r, out) = ctl(&s, &["hosts"]).await;
    assert!(r.is_ok());
    assert!(out.contains("HOST") && out.contains("h1") && out.contains("ok"));
    let (_, out) = ctl(&s, &["guests", "--status", "stopped"]).await;
    assert!(out.contains("103") && !out.contains("9001"));
    let (_, out) = ctl(&s, &["guest", "h1", "103"]).await;
    assert!(out.contains("config:") && out.contains("rootfs"));
    let (_, out) = ctl(&s, &["version"]).await;
    assert!(!out.trim().is_empty());
}

#[tokio::test]
async fn errors_are_reported() {
    let s = start(false).await;
    let (r, _) = ctl(&s, &["guest", "h1", "4242"]).await;
    assert!(matches!(
        r,
        Err(concordctl::CtlError::Server { status: 404, .. })
    ));
    let (r, _) = ctl(&s, &["guests", "--host", "typo"]).await;
    assert!(matches!(
        r,
        Err(concordctl::CtlError::Server { status: 404, .. })
    ));
    let (r, _) = raw("http://127.0.0.1:1", &["hosts"]).await;
    assert!(matches!(r, Err(concordctl::CtlError::Connect { .. })));
}

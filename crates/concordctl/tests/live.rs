use std::sync::Arc;

use clap::Parser;
use concord_inventory::{InventoryConfig, Poller};
use concord_pve::{FixtureSet, PveApi};
use concord_server::{router, AppState};
use concordctl::{run, Cli};

/// Starts the real router on an ephemeral port, one cycle already published.
async fn server() -> String {
    let set = FixtureSet::committed("9.2.21").expect("fixture");
    let client: Arc<dyn PveApi> = Arc::new(set.mock());
    let (mut poller, inventory) =
        Poller::new(vec![("h1".into(), client)], InventoryConfig::default());
    poller.run_cycle().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(AppState { inventory })).await;
    });
    format!("http://{addr}")
}

async fn ctl(server: &str, args: &[&str]) -> (Result<(), concordctl::CtlError>, String) {
    let mut argv = vec!["concordctl", "--server", server];
    argv.extend_from_slice(args);
    let cli = Cli::parse_from(argv);
    let mut out = Vec::new();
    let r = run(&cli, &mut out).await;
    (r, String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn json_output_is_the_api_body() {
    let s = server().await;
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
    let s = server().await;
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
    let s = server().await;
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
    let (r, _) = ctl("http://127.0.0.1:1", &["hosts"]).await;
    assert!(matches!(r, Err(concordctl::CtlError::Connect { .. })));
}

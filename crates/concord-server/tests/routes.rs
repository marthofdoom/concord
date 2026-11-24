use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use concord_inventory::{InventoryConfig, Poller};
use concord_pve::{FixtureSet, PveApi};
use concord_server::{router, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, serde_json::from_slice(&bytes).expect("json"))
}

async fn app(cycles: usize) -> axum::Router {
    let set = FixtureSet::committed("9.2.21").expect("fixture");
    let client: Arc<dyn PveApi> = Arc::new(set.mock());
    let (mut poller, inventory) =
        Poller::new(vec![("h1".into(), client)], InventoryConfig::default());
    for _ in 0..cycles {
        poller.run_cycle().await;
    }
    router(AppState { inventory })
}

#[tokio::test]
async fn health_and_version_need_no_inventory() {
    let a = app(0).await;
    assert_eq!(get(&a, "/healthz").await.0, StatusCode::OK);
    let (s, v) = get(&a, "/api/v1/version").await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["version"].is_string());
}

#[tokio::test]
async fn inventory_routes_are_503_before_first_cycle() {
    let a = app(0).await;
    for uri in [
        "/api/v1/estate",
        "/api/v1/hosts",
        "/api/v1/guests",
        "/api/v1/guests/h1/101",
    ] {
        let (s, v) = get(&a, uri).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert!(v["error"].is_string());
    }
}

#[tokio::test]
async fn estate_and_hosts() {
    let a = app(1).await;
    let (s, v) = get(&a, "/api/v1/estate").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["cycle"], 1);
    assert_eq!(v["hosts"][0]["guests"].as_array().map(Vec::len), Some(5));
    // The estate view carries config; hosts must not carry guests.
    assert!(v["hosts"][0]["guests"][0]["config"].is_object());
    let (s, v) = get(&a, "/api/v1/hosts").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["hosts"][0]["guest_count"], 5);
    assert!(v["hosts"][0].get("guests").is_none());
}

#[tokio::test]
async fn guest_list_filters_and_omits_config() {
    let a = app(1).await;
    let (_, v) = get(&a, "/api/v1/guests").await;
    let all = v["guests"].as_array().expect("array");
    assert_eq!(all.len(), 5);
    assert!(all
        .iter()
        .all(|g| g.get("config").is_none() && g["host"] == "h1"));
    let (_, v) = get(&a, "/api/v1/guests?kind=lxc").await;
    assert_eq!(v["guests"].as_array().map(Vec::len), Some(3));
    let (_, v) = get(&a, "/api/v1/guests?kind=qemu&status=running").await;
    assert_eq!(v["guests"].as_array().map(Vec::len), Some(1));
    let (_, v) = get(&a, "/api/v1/guests?host=nope").await;
    assert_eq!(v["guests"].as_array().map(Vec::len), Some(0));
    let (s, _) = get(&a, "/api/v1/guests?kind=bogus").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn single_guest_and_404() {
    let a = app(1).await;
    let (s, v) = get(&a, "/api/v1/guests/h1/103").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["vmid"], 103);
    assert!(v["config"].is_object());
    let (s, v) = get(&a, "/api/v1/guests/h1/4242").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(v["error"].is_string());
    let (s, _) = get(&a, "/api/v1/guests/nohost/103").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_core::GuestKind;
use concord_pve::{FixtureSet, Method, MockPve, PveApi, PveError};
use serde_json::{json, Value};

use crate::*;

fn cfg() -> InventoryConfig {
    InventoryConfig {
        interval: Duration::from_secs(1),
        host_deadline: Duration::from_millis(200),
        detail_concurrency: 4,
    }
}

fn arc(m: MockPve) -> Arc<dyn PveApi> {
    Arc::new(m)
}

fn nodes_json(nodes: &[(&str, &str)]) -> Value {
    Value::Array(
        nodes
            .iter()
            .map(|(n, s)| json!({"node": n, "status": s}))
            .collect(),
    )
}

fn base(nodes: Value) -> MockPve {
    MockPve::new().on(Method::Get, "/nodes", nodes).on(
        Method::Get,
        "/version",
        json!({"version": "9.2.21", "release": "9.2", "repoid": "x"}),
    )
}

/// Registers the detail routes for one guest.
fn guest(m: MockPve, node: &str, kind: &str, vmid: u32, status: &str) -> MockPve {
    m.on(
        Method::Get,
        &format!("/nodes/{node}/{kind}/{vmid}/config"),
        json!({"memory": 512, "cipassword": "hunter2", "sshkeys": "fake-public-key", "description": "note"}),
    )
    .on(
        Method::Get,
        &format!("/nodes/{node}/{kind}/{vmid}/status/current"),
        json!({"vmid": vmid, "status": status}),
    )
}

fn lst(m: MockPve, node: &str, kind: &str, items: Value) -> MockPve {
    m.on(Method::Get, &format!("/nodes/{node}/{kind}"), items)
}

fn simple(vmids: &[u32]) -> MockPve {
    let mut m = base(nodes_json(&[("n1", "online")]));
    let items: Vec<Value> = vmids
        .iter()
        .map(|v| json!({"vmid": v, "name": format!("g{v}"), "status": "running"}))
        .collect();
    m = lst(m, "n1", "qemu", Value::Array(items));
    m = lst(m, "n1", "lxc", json!([]));
    for v in vmids {
        m = guest(m, "n1", "qemu", *v, "running");
    }
    m
}

fn snap(h: &InventoryHandle) -> Arc<EstateSnapshot> {
    h.current().expect("snapshot")
}

#[tokio::test]
async fn nothing_published_before_first_cycle() {
    let (_p, h) = Poller::new(vec![("a".into(), arc(simple(&[1])))], cfg());
    assert!(h.current().is_none());
}

#[tokio::test]
async fn fixture_estate_is_read() {
    let set = FixtureSet::committed("9.2.21").expect("fixture");
    let (mut p, h) = Poller::new(vec![("a".into(), arc(set.mock()))], cfg());
    p.run_cycle().await;
    let s = snap(&h);
    assert_eq!(s.cycle, 1);
    let host = &s.hosts[0];
    assert_eq!(host.status, HostStatus::Ok);
    assert_eq!(host.node.as_deref(), Some("node1"));
    assert_eq!(host.pve_version.as_deref(), Some("9.2.21"));
    let ids: Vec<u32> = host.guests.iter().map(|g| g.vmid).collect();
    assert_eq!(ids, vec![101, 102, 103, 9001, 9106]);
    let g103 = host.guests.iter().find(|g| g.vmid == 103).expect("103");
    assert_eq!(g103.kind, GuestKind::Lxc);
    assert_eq!(g103.status, "stopped");
    assert!(g103
        .config
        .as_ref()
        .is_some_and(|c| c.contains_key("rootfs")));
    let g9001 = host.guests.iter().find(|g| g.vmid == 9001).expect("9001");
    assert_eq!(g9001.tags, vec!["tag-3"]);
    assert!(s.conflicts.is_empty());
}

#[tokio::test]
async fn failed_host_keeps_guests_stale_then_recovers() {
    // /nodes answers ok, fails, ok: one route, three cycles.
    let m = MockPve::new()
        .on(Method::Get, "/nodes", nodes_json(&[("n1", "online")]))
        .on_err(Method::Get, "/nodes", PveError::Connect("down".into()))
        .on(Method::Get, "/nodes", nodes_json(&[("n1", "online")]))
        .on(
            Method::Get,
            "/version",
            json!({"version":"9.2.21","release":"9.2","repoid":"x"}),
        )
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"status":"running"},{"vmid":2,"status":"running"}]),
        )
        .on(Method::Get, "/nodes/n1/lxc", json!([]));
    let m = guest(
        guest(m, "n1", "qemu", 1, "running"),
        "n1",
        "qemu",
        2,
        "running",
    );
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    let first = snap(&h);
    let ok_at = first.hosts[0].last_success;
    assert!(ok_at.is_some());
    p.run_cycle().await;
    let s = snap(&h);
    let host = &s.hosts[0];
    assert_eq!(host.status, HostStatus::Unreachable);
    assert!(host.error.as_deref().is_some_and(|e| e.contains("down")));
    assert_eq!(host.guests.len(), 2);
    assert!(host.guests.iter().all(|g| g.stale));
    assert_eq!(host.last_success, ok_at);
    p.run_cycle().await;
    let s = snap(&h);
    let host = &s.hosts[0];
    assert_eq!(host.status, HostStatus::Ok);
    assert!(host.error.is_none());
    assert!(host.guests.iter().all(|g| !g.stale));
}

#[tokio::test]
async fn successful_omission_deletes_guest() {
    let m = base(nodes_json(&[("n1", "online")]))
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"status":"running"},{"vmid":2,"status":"running"}]),
        )
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"status":"running"}]),
        )
        .on(Method::Get, "/nodes/n1/lxc", json!([]));
    let m = guest(
        guest(m, "n1", "qemu", 1, "running"),
        "n1",
        "qemu",
        2,
        "running",
    );
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    assert_eq!(snap(&h).hosts[0].guests.len(), 2);
    p.run_cycle().await;
    let g = &snap(&h).hosts[0].guests;
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].vmid, 1);
}

#[tokio::test]
async fn lxc_failure_fails_the_host_and_keeps_containers() {
    let m = base(nodes_json(&[("n1", "online")]))
        .on(Method::Get, "/nodes/n1/qemu", json!([]))
        .on(
            Method::Get,
            "/nodes/n1/lxc",
            json!([{"vmid":5,"status":"running"}]),
        )
        .on_err(Method::Get, "/nodes/n1/lxc", PveError::Timeout);
    let m = guest(m, "n1", "lxc", 5, "running");
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    p.run_cycle().await;
    let host = snap(&h).hosts[0].clone();
    assert_eq!(host.status, HostStatus::Unreachable);
    assert_eq!(host.guests.len(), 1);
    assert!(host.guests[0].stale);
}

/// Never answers.
struct Hung;

#[async_trait]
impl PveApi for Hung {
    async fn request(
        &self,
        _m: Method,
        _p: &str,
        _q: &[(&str, String)],
    ) -> Result<Value, PveError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn slow_host_does_not_stall_others() {
    let (mut p, h) = Poller::new(
        vec![
            ("slow".into(), Arc::new(Hung) as Arc<dyn PveApi>),
            ("fast".into(), arc(simple(&[7]))),
        ],
        cfg(),
    );
    let started = std::time::Instant::now();
    p.run_cycle().await;
    assert!(started.elapsed() < Duration::from_secs(2));
    let s = snap(&h);
    assert_eq!(s.hosts[0].status, HostStatus::Unreachable);
    assert!(s.hosts[0].error.is_some());
    assert_eq!(s.hosts[1].status, HostStatus::Ok);
    assert_eq!(s.hosts[1].guests.len(), 1);
}

#[tokio::test]
async fn snapshot_swaps_atomically() {
    let m = base(nodes_json(&[("n1", "online")]))
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"status":"running"}]),
        )
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"status":"running"},{"vmid":2,"status":"running"}]),
        )
        .on(Method::Get, "/nodes/n1/lxc", json!([]));
    let m = guest(
        guest(m, "n1", "qemu", 1, "running"),
        "n1",
        "qemu",
        2,
        "running",
    );
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    let old = snap(&h);
    p.run_cycle().await;
    let new = snap(&h);
    // A reader holding the old snapshot is unaffected by the swap.
    assert_eq!(old.cycle, 1);
    assert_eq!(old.hosts[0].guests.len(), 1);
    assert_eq!(new.cycle, 2);
    assert_eq!(new.hosts[0].guests.len(), 2);
}

#[tokio::test]
async fn same_vmid_on_two_hosts_is_a_conflict() {
    let (mut p, h) = Poller::new(
        vec![
            ("a".into(), arc(simple(&[100, 101]))),
            ("b".into(), arc(simple(&[100]))),
        ],
        cfg(),
    );
    p.run_cycle().await;
    let s = snap(&h);
    assert_eq!(
        s.conflicts,
        vec![Conflict {
            vmid: 100,
            hosts: vec!["a".into(), "b".into()]
        }]
    );
    // Not merged.
    assert_eq!(s.hosts[0].guests.len(), 2);
    assert_eq!(s.hosts[1].guests.len(), 1);
}

#[tokio::test]
async fn secret_config_keys_are_stripped() {
    let (mut p, h) = Poller::new(vec![("a".into(), arc(simple(&[1])))], cfg());
    p.run_cycle().await;
    let s = snap(&h);
    let cfgmap = s.hosts[0].guests[0].config.as_ref().expect("config");
    assert!(cfgmap.contains_key("memory"));
    for k in SECRET_CONFIG_KEYS {
        assert!(!cfgmap.contains_key(*k), "{k} leaked");
    }
    let text = serde_json::to_string(&*s).expect("json");
    assert!(!text.contains("hunter2") && !text.contains("fake-public-key"));
}

#[tokio::test]
async fn detail_failure_keeps_list_data() {
    let m = base(nodes_json(&[("n1", "online")]))
        .on(
            Method::Get,
            "/nodes/n1/qemu",
            json!([{"vmid":1,"name":"web","status":"weirdstate","maxmem":1024,"template":1,"tags":"a;b"}]),
        )
        .on(Method::Get, "/nodes/n1/lxc", json!([]));
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    let s = snap(&h);
    assert_eq!(s.hosts[0].status, HostStatus::Ok);
    let g = &s.hosts[0].guests[0];
    assert_eq!(g.status, "weirdstate");
    assert_eq!(g.name.as_deref(), Some("web"));
    assert_eq!(g.maxmem, Some(1024));
    assert!(g.template);
    assert_eq!(g.tags, vec!["a", "b"]);
    assert!(g.config.is_none());
    assert!(g
        .detail_error
        .as_deref()
        .is_some_and(|e| e.contains("config")));
}

#[tokio::test]
async fn offline_cluster_node_guests_go_stale() {
    let both = nodes_json(&[("n1", "online"), ("n2", "online")]);
    let one_down = nodes_json(&[("n1", "online"), ("n2", "offline")]);
    let mut m = MockPve::new()
        .on(Method::Get, "/nodes", both)
        .on(Method::Get, "/nodes", one_down)
        .on(
            Method::Get,
            "/version",
            json!({"version":"9.2.21","release":"9.2","repoid":"x"}),
        );
    m = lst(m, "n1", "qemu", json!([{"vmid":1,"status":"running"}]));
    m = lst(m, "n1", "lxc", json!([]));
    m = lst(m, "n2", "qemu", json!([{"vmid":2,"status":"running"}]));
    m = lst(m, "n2", "lxc", json!([]));
    m = guest(
        guest(m, "n1", "qemu", 1, "running"),
        "n2",
        "qemu",
        2,
        "running",
    );
    let (mut p, h) = Poller::new(vec![("a".into(), arc(m))], cfg());
    p.run_cycle().await;
    assert!(snap(&h).hosts[0].guests.iter().all(|g| !g.stale));
    p.run_cycle().await;
    let s = snap(&h);
    let host = &s.hosts[0];
    assert_eq!(host.status, HostStatus::Ok);
    let g1 = host.guests.iter().find(|g| g.vmid == 1).expect("1");
    let g2 = host.guests.iter().find(|g| g.vmid == 2).expect("2");
    assert!(!g1.stale);
    assert!(g2.stale);
}

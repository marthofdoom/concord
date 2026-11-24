//! The status view: one background poller, one cached snapshot.
//!
//! The browser polls nestview, not PVE: pveproxy has only a few workers, so
//! however many tabs are open the host sees one set of GETs per refresh.
//!
//! Every field is either a value taken from a real API response or the error
//! that GET returned (a 403 included), never a guess.

use std::time::Duration;

use concord_pve::{Method, PveApi, PveError};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::audit::now_rfc3339;
use crate::estate::{paths, Node, Vmid, ZONE};

/// The host-guard hook lives in /etc/network/if-up.d on the host. No PVE API call
/// exposes it, and the container cannot see the host's filesystem, so this
/// is said rather than inferred.
pub const HOST_GUARD: &str = "unknown (not visible to container)";

/// How many of a VM's recent tasks to show.
const TASK_LIMIT: u32 = 10;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Field<T> {
    Ok(T),
    Error(String),
}

impl<T> Field<T> {
    fn from(r: Result<T, PveError>) -> Self {
        match r {
            Ok(v) => Field::Ok(v),
            Err(e) => Field::Error(e.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub fetched_at: String,
    pub vms: Vec<VmView>,
    pub estate: EstateView,
}

#[derive(Clone, Debug, Serialize)]
pub struct VmView {
    pub vmid: u32,
    pub expected_name: String,
    /// Selected keys of `status/current`, as PVE returned them.
    pub status: Field<Value>,
    pub config: Field<ConfigView>,
    pub ip: Field<IpView>,
    /// `GET .../snapshot` items, as returned (the `current` pseudo-entry
    /// included; the UI marks it).
    pub snapshots: Field<Value>,
    /// `GET /nodes/{node}/tasks?vmid=..`, as returned. PVE lists only the
    /// tasks this token started unless it has Sys.Audit on the node
    /// (pve-manager API2/Tasks.pm), and the nest token does not.
    pub tasks: Field<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigView {
    pub net0: Option<String>,
    /// The same test darken.sh uses: `link_down=1` anywhere in net0.
    pub link_down: bool,
    pub watchdog: Option<String>,
    pub agent: Option<String>,
    pub agent_enabled: bool,
    pub ipconfig0: Option<String>,
    pub tags: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IpView {
    /// `guest-agent` or `ipconfig0`.
    pub source: &'static str,
    pub addresses: Vec<String>,
    /// Why the agent was not used when it is enabled (not running, error).
    pub agent_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EstateView {
    /// This node's entry for the zone from `GET /nodes/{node}/sdn/zones`.
    /// `/cluster/sdn/zones` lists nothing for the nest token (its SDN ACL is
    /// on the vnet path), so the node view is the one it can read.
    pub zone: Field<Value>,
    pub vnet: Field<Value>,
    pub storage: Field<Value>,
    pub host_guard: &'static str,
}

const STATUS_KEYS: &[&str] = &[
    "name",
    "status",
    "qmpstatus",
    "uptime",
    "cpu",
    "cpus",
    "mem",
    "maxmem",
    "disk",
    "maxdisk",
    "agent",
    "lock",
];

pub async fn collect(api: &dyn PveApi, node: &Node) -> Snapshot {
    let mut vms = Vec::new();
    for vmid in Vmid::all() {
        vms.push(collect_vm(api, node, vmid).await);
    }
    Snapshot {
        fetched_at: now_rfc3339(),
        vms,
        estate: collect_estate(api, node).await,
    }
}

async fn get(api: &dyn PveApi, path: Result<String, PveError>) -> Result<Value, PveError> {
    api.request(Method::Get, &path?, &[]).await
}

async fn collect_vm(api: &dyn PveApi, node: &Node, vmid: Vmid) -> VmView {
    let status = get(api, paths::status_current(node, vmid))
        .await
        .map(|v| pick(&v, STATUS_KEYS));
    let run_state = match &status {
        Ok(v) => qmp_state(v),
        Err(_) => "unknown".to_string(),
    };

    let config = get(api, paths::config(node, vmid))
        .await
        .map(|v| config_view(&v));

    let ip = match &config {
        Ok(c) => Ok(ip_view(api, node, vmid, c, &run_state).await),
        Err(e) => Err(e.clone()),
    };

    let snapshots = get(api, paths::snapshots(node, vmid)).await;

    let tasks = match paths::node_tasks(node) {
        Ok(p) => {
            api.request(
                Method::Get,
                &p,
                &[
                    ("vmid", vmid.to_string()),
                    ("limit", TASK_LIMIT.to_string()),
                ],
            )
            .await
        }
        Err(e) => Err(e),
    };

    VmView {
        vmid: vmid.get(),
        expected_name: vmid.expected_name(),
        status: Field::from(status),
        config: Field::from(config),
        ip: Field::from(ip),
        snapshots: Field::from(snapshots),
        tasks: Field::from(tasks),
    }
}

/// darken.sh's `.qmpstatus // .status`: in `status/current` a paused or
/// suspended VM still has `status: running` (the QEMU process exists), and
/// only `qmpstatus` says otherwise. `/cluster/resources` is not
/// read here; its `status` is already `qmpstatus || status` and reads
/// "paused" for such a VM.
fn qmp_state(v: &Value) -> String {
    let pick = |k: &str| match v.get(k) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    };
    pick("qmpstatus")
        .or_else(|| pick("status"))
        .unwrap_or_else(|| "null".into())
}

fn pick(v: &Value, keys: &[&str]) -> Value {
    let mut out = Map::new();
    for k in keys {
        if let Some(x) = v.get(*k) {
            out.insert((*k).to_string(), x.clone());
        }
    }
    Value::Object(out)
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

pub fn config_view(cfg: &Value) -> ConfigView {
    let net0 = str_field(cfg, "net0");
    let agent = str_field(cfg, "agent");
    ConfigView {
        link_down: net0.as_deref().is_some_and(|n| n.contains("link_down=1")),
        agent_enabled: agent.as_deref().is_some_and(agent_enabled),
        net0,
        watchdog: str_field(cfg, "watchdog"),
        agent,
        ipconfig0: str_field(cfg, "ipconfig0"),
        tags: str_field(cfg, "tags"),
    }
}

/// PVE's `agent` property: `[enabled=]<1|0>[,fstrim_cloned_disks=..][,type=..]`
/// (qemu-server). Observed on the nested nodes as the string `"1"`.
fn agent_enabled(agent: &str) -> bool {
    let first = agent.split(',').next().unwrap_or("");
    let v = first.strip_prefix("enabled=").unwrap_or(first);
    matches!(v, "1" | "yes" | "on" | "true")
}

async fn ip_view(
    api: &dyn PveApi,
    node: &Node,
    vmid: Vmid,
    c: &ConfigView,
    run_state: &str,
) -> IpView {
    let fallback = |agent_error: Option<String>| IpView {
        source: "ipconfig0",
        addresses: c
            .ipconfig0
            .as_deref()
            .map(ipconfig_addresses)
            .unwrap_or_default(),
        agent_error,
    };
    if !c.agent_enabled {
        return fallback(None);
    }
    // Only a VM QEMU reports as running answers the agent. Asking a paused one
    // costs a pveproxy worker the agent ping's 3 s timeout every cycle.
    if run_state != "running" {
        return fallback(Some(format!("VM is {run_state}; guest agent not queried")));
    }
    match get(api, paths::agent_interfaces(node, vmid)).await {
        Ok(v) => match agent_addresses(&v) {
            Some(addresses) => IpView {
                source: "guest-agent",
                addresses,
                agent_error: None,
            },
            None => fallback(Some("unexpected guest-agent response shape".into())),
        },
        Err(e) => fallback(Some(e.to_string())),
    }
}

/// `ip=10.99.0.11/24,gw=10.99.0.1` -> `["10.99.0.11/24"]`; also `ip6=`.
fn ipconfig_addresses(ipconfig: &str) -> Vec<String> {
    ipconfig
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| *k == "ip" || *k == "ip6")
        .map(|(_, v)| v.to_string())
        .collect()
}

/// PVE wraps the agent reply as `{"result": ...}` (qemu-server
/// API2/Qemu/Agent.pm). The items follow QEMU's `guest-network-get-interfaces`:
/// `name`, `ip-addresses: [{ip-address, prefix, ...}]` (observed on a
/// real node). Loopback is skipped.
fn agent_addresses(v: &Value) -> Option<Vec<String>> {
    let ifaces = v.get("result")?.as_array()?;
    let mut out = Vec::new();
    for i in ifaces {
        let name = i.get("name").and_then(Value::as_str).unwrap_or("?");
        if name == "lo" {
            continue;
        }
        for a in i
            .get("ip-addresses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(ip) = a.get("ip-address").and_then(Value::as_str) {
                let prefix = a.get("prefix").and_then(Value::as_u64);
                out.push(match prefix {
                    Some(p) => format!("{name}: {ip}/{p}"),
                    None => format!("{name}: {ip}"),
                });
            }
        }
    }
    Some(out)
}

async fn collect_estate(api: &dyn PveApi, node: &Node) -> EstateView {
    let zone = get(api, paths::node_sdn_zones(node)).await.and_then(|v| {
        v.as_array()
            .and_then(|a| {
                a.iter()
                    .find(|z| z.get("zone").and_then(Value::as_str) == Some(ZONE))
                    .cloned()
            })
            .ok_or_else(|| {
                PveError::Decode(format!("zone {ZONE} is not in this node's SDN zone list"))
            })
    });
    let vnet = get(api, paths::vnet()).await;
    let storage = get(api, paths::storage_status(node)).await;
    EstateView {
        zone: Field::from(zone),
        vnet: Field::from(vnet),
        storage: Field::from(storage),
        host_guard: HOST_GUARD,
    }
}

/// Re-collects every `every`, or at once when `kick` fires (after a control
/// ran), and publishes the result.
pub async fn run_poller(
    api: std::sync::Arc<dyn PveApi>,
    node: Node,
    every: Duration,
    out: tokio::sync::watch::Sender<Option<std::sync::Arc<Snapshot>>>,
    kick: std::sync::Arc<tokio::sync::Notify>,
) {
    loop {
        let snap = collect(api.as_ref(), &node).await;
        out.send_replace(Some(std::sync::Arc::new(snap)));
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = kick.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use concord_pve::MockPve;
    use serde_json::json;

    #[test]
    fn config_view_reads_observed_shape() {
        // From a real GET .../qemu/9001/config.
        let cfg = json!({"agent":"1","net0":"virtio=02:00:00:00:00:01,bridge=cnest",
            "ipconfig0":"ip=10.99.0.11/24,gw=10.99.0.1","watchdog":"model=i6300esb,action=reset",
            "tags":"concord-nest"});
        let c = config_view(&cfg);
        assert!(c.agent_enabled);
        assert!(!c.link_down);
        assert_eq!(c.watchdog.as_deref(), Some("model=i6300esb,action=reset"));
        assert_eq!(
            ipconfig_addresses(c.ipconfig0.as_deref().unwrap()),
            vec!["10.99.0.11/24"]
        );
        assert!(!agent_enabled("enabled=0,type=virtio"));
        assert!(agent_enabled("enabled=1"));
    }

    #[test]
    fn agent_addresses_from_captured_response() {
        // GET /nodes/pve1/qemu/9001/agent/network-get-interfaces with the nest
        // token (statistics trimmed).
        let v = json!({"result": [
            {"name": "lo", "hardware-address": "00:00:00:00:00:00", "ip-addresses": [
                {"prefix": 8, "ip-address-type": "ipv4", "ip-address": "127.0.0.1"},
                {"prefix": 128, "ip-address-type": "ipv6", "ip-address": "::1"}]},
            {"name": "eth0", "hardware-address": "02:00:00:00:00:01", "ip-addresses": [
                {"prefix": 24, "ip-address-type": "ipv4", "ip-address": "10.99.0.11"},
                {"prefix": 64, "ip-address-type": "ipv6", "ip-address": "2001:db8::11"}]}
        ]});
        assert_eq!(
            agent_addresses(&v).unwrap(),
            vec!["eth0: 10.99.0.11/24", "eth0: 2001:db8::11/64"]
        );
        assert!(agent_addresses(&json!({"oops": 1})).is_none());
    }

    #[tokio::test]
    async fn paused_vm_agent_is_not_queried() {
        let node = Node::new("pve1").unwrap();
        let api = MockPve::new()
            .on(
                Method::Get,
                "/nodes/pve1/qemu/9001/status/current",
                json!({"status": "running", "qmpstatus": "paused", "name": "nest1"}),
            )
            .on(
                Method::Get,
                "/nodes/pve1/qemu/9001/config",
                json!({"agent": "1", "ipconfig0": "ip=10.99.0.11/24,gw=10.99.0.1"}),
            );
        let v = collect_vm(&api, &node, Vmid::new(9001).unwrap()).await;
        let Field::Ok(ip) = &v.ip else {
            panic!("ip field: {:?}", v.ip)
        };
        assert_eq!(ip.source, "ipconfig0");
        assert_eq!(
            ip.agent_error.as_deref(),
            Some("VM is paused; guest agent not queried")
        );
        assert!(!api.calls().iter().any(|c| c.path.contains("/agent/")));
        assert_eq!(
            qmp_state(&json!({"status": "running", "qmpstatus": null})),
            "running"
        );
        assert_eq!(qmp_state(&json!({"status": "stopped"})), "stopped");
    }

    #[tokio::test]
    async fn errors_are_shown_not_hidden() {
        let node = Node::new("pve1").unwrap();
        // Nothing registered: every GET fails, and every field says so.
        let api = MockPve::new().on_err(
            Method::Get,
            "/nodes/pve1/sdn/zones",
            PveError::Http {
                status: 403,
                message: "Permission check failed (/sdn/zones/cnestz, SDN.Audit)\n".into(),
                errors: None,
            },
        );
        let s = collect(&api, &node).await;
        assert!(matches!(&s.estate.zone, Field::Error(e) if e.contains("403")));
        assert!(matches!(&s.vms[0].status, Field::Error(_)));
        assert_eq!(s.estate.host_guard, HOST_GUARD);
        // Only GETs.
        assert!(api.calls().iter().all(|c| c.method == Method::Get));
    }
}

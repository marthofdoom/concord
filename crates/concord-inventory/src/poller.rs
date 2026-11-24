use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use concord_core::GuestKind;
use concord_pve::{api_path, Method, NodeStatus, PveApi, PveError};
use futures_util::future::join_all;
use futures_util::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::types::{Conflict, EstateSnapshot, Guest, Host, HostStatus};

/// Config keys that can hold credentials or free text an operator typed in
/// confidence. The snapshot is served over an API with no auth yet, so these
/// never enter it.
pub const SECRET_CONFIG_KEYS: &[&str] = &["cipassword", "sshkeys", "description"];

/// Longest error text kept in the snapshot.
const MAX_ERROR_CHARS: usize = 300;

#[derive(Clone, Copy, Debug)]
pub struct InventoryConfig {
    /// Pause between the end of one cycle and the start of the next.
    pub interval: Duration,
    /// Upper bound on polling one host. Without it one hung host would hold
    /// the whole cycle, and so every other host's fresh data, hostage.
    pub host_deadline: Duration,
    /// Concurrent per-guest detail calls per host: a host with hundreds of
    /// guests must not be hit with hundreds of requests at once.
    pub detail_concurrency: usize,
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            host_deadline: Duration::from_secs(30),
            detail_concurrency: 8,
        }
    }
}

/// Read side of the inventory. Cheap to clone.
#[derive(Clone)]
pub struct InventoryHandle {
    rx: watch::Receiver<Option<Arc<EstateSnapshot>>>,
}

impl InventoryHandle {
    /// The latest snapshot, or `None` until the first cycle has finished.
    pub fn current(&self) -> Option<Arc<EstateSnapshot>> {
        self.rx.borrow().clone()
    }
}

struct HostEntry {
    name: String,
    client: Arc<dyn PveApi>,
    /// Last-known state; what a failed poll falls back to.
    last: Host,
}

pub struct Poller {
    hosts: Vec<HostEntry>,
    cfg: InventoryConfig,
    cycle: u64,
    tx: watch::Sender<Option<Arc<EstateSnapshot>>>,
}

impl Poller {
    /// `hosts` is (operator's host name, client).
    pub fn new(
        hosts: Vec<(String, Arc<dyn PveApi>)>,
        cfg: InventoryConfig,
    ) -> (Self, InventoryHandle) {
        let (tx, rx) = watch::channel(None);
        let hosts = hosts
            .into_iter()
            .map(|(name, client)| HostEntry {
                last: Host {
                    name: name.clone(),
                    node: None,
                    status: HostStatus::Pending,
                    error: None,
                    pve_version: None,
                    last_success: None,
                    guests: Vec::new(),
                },
                name,
                client,
            })
            .collect();
        (
            Self {
                hosts,
                cfg,
                cycle: 0,
                tx,
            },
            InventoryHandle { rx },
        )
    }

    /// Polls forever. Spawn it; it ends with the runtime.
    pub async fn run(mut self) {
        loop {
            self.run_cycle().await;
            tokio::time::sleep(self.cfg.interval).await;
        }
    }

    /// One cycle: poll every host concurrently, then publish the whole result
    /// in one swap.
    pub async fn run_cycle(&mut self) {
        let deadline = self.cfg.host_deadline;
        let conc = self.cfg.detail_concurrency.max(1);
        let futs = self.hosts.iter().map(|h| {
            let client = h.client.clone();
            let prev = h.last.clone();
            async move {
                match tokio::time::timeout(deadline, poll_host(client, &prev, conc)).await {
                    Ok(host) => host,
                    Err(_) => failed(
                        &prev,
                        format!("poll did not finish within {}s", deadline.as_secs()),
                    ),
                }
            }
        });
        let polled = join_all(futs).await;
        for (entry, host) in self.hosts.iter_mut().zip(polled) {
            if host.status == HostStatus::Unreachable {
                tracing::warn!(host = %entry.name, error = host.error.as_deref().unwrap_or(""), "host poll failed");
            }
            entry.last = host;
        }
        self.cycle += 1;
        let hosts: Vec<Host> = self.hosts.iter().map(|h| h.last.clone()).collect();
        let snap = EstateSnapshot {
            cycle: self.cycle,
            taken_at: now_secs(),
            conflicts: conflicts(&hosts),
            hosts,
        };
        self.tx.send_replace(Some(Arc::new(snap)));
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Error text for the snapshot: bounded, and with control characters removed
/// because it is rendered by terminals and UIs.
fn clean(e: impl Display) -> String {
    e.to_string()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// The previous state, marked stale. Guests are kept: a host that stopped
/// answering has not lost its guests, and dropping them would look to every
/// consumer like a mass deletion.
fn failed(prev: &Host, error: String) -> Host {
    let mut h = prev.clone();
    h.status = HostStatus::Unreachable;
    h.error = Some(error);
    for g in &mut h.guests {
        g.stale = true;
    }
    h
}

fn conflicts(hosts: &[Host]) -> Vec<Conflict> {
    let mut by_vmid: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for h in hosts {
        for g in &h.guests {
            let v = by_vmid.entry(g.vmid).or_default();
            if !v.contains(&h.name) {
                v.push(h.name.clone());
            }
        }
    }
    by_vmid
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(vmid, hosts)| Conflict { vmid, hosts })
        .collect()
}

async fn poll_host(client: Arc<dyn PveApi>, prev: &Host, conc: usize) -> Host {
    match poll_host_inner(&client, prev, conc).await {
        Ok(h) => h,
        Err(e) => failed(prev, clean(e)),
    }
}

async fn poll_host_inner(
    client: &Arc<dyn PveApi>,
    prev: &Host,
    conc: usize,
) -> Result<Host, PveError> {
    let nodes = client.nodes().await?;
    if nodes.is_empty() {
        return Err(PveError::Decode("PVE reported no nodes".into()));
    }
    // A standalone host answers for exactly one node, whatever its status
    // field says. Only a real cluster has nodes we know to skip.
    let single = nodes.len() == 1;
    let (live, down): (Vec<_>, Vec<_>) = nodes
        .iter()
        .partition(|n| single || n.status == NodeStatus::Online);

    // Not fatal: the version is context, not inventory.
    let pve_version = match client.version().await {
        Ok(v) => Some(v.version),
        Err(_) => prev.pve_version.clone(),
    };

    let mut listed: Vec<(String, GuestKind, Item)> = Vec::new();
    for n in &live {
        // Both lists or neither: qemu without lxc would make every container
        // look deleted.
        let (q, l) = tokio::join!(
            list(client, &n.node, GuestKind::Qemu),
            list(client, &n.node, GuestKind::Lxc)
        );
        for item in q? {
            listed.push((n.node.clone(), GuestKind::Qemu, item));
        }
        for item in l? {
            listed.push((n.node.clone(), GuestKind::Lxc, item));
        }
    }

    let results: Vec<Result<Guest, PveError>> = stream::iter(listed)
        .map(|(node, kind, item)| detail(client.clone(), node, kind, item))
        .buffer_unordered(conc)
        .collect()
        .await;
    let mut guests = results.into_iter().collect::<Result<Vec<_>, _>>()?;

    // An offline cluster node's guests are kept as last seen, stale.
    for n in &down {
        guests.extend(prev.guests.iter().filter(|g| g.node == n.node).map(|g| {
            let mut g = g.clone();
            g.stale = true;
            g
        }));
    }
    guests.sort_by_key(|g| (g.vmid, g.node.clone()));

    Ok(Host {
        name: prev.name.clone(),
        node: live.first().map(|n| n.node.clone()),
        status: HostStatus::Ok,
        error: None,
        pve_version,
        last_success: Some(now_secs()),
        guests,
    })
}

/// A list or `status/current` entry. Everything PVE may omit is optional.
#[derive(Clone, Debug, Default, Deserialize)]
struct Item {
    vmid: Option<u32>,
    name: Option<String>,
    status: Option<String>,
    cpus: Option<f64>,
    maxmem: Option<u64>,
    mem: Option<u64>,
    uptime: Option<u64>,
    template: Option<Value>,
    tags: Option<String>,
}

fn kind_segment(kind: GuestKind) -> &'static str {
    match kind {
        GuestKind::Qemu => "qemu",
        GuestKind::Lxc => "lxc",
    }
}

async fn list(
    client: &Arc<dyn PveApi>,
    node: &str,
    kind: GuestKind,
) -> Result<Vec<Item>, PveError> {
    let path = api_path(&["nodes", node, kind_segment(kind)])?;
    let v = client.request(Method::Get, &path, &[]).await?;
    let items: Vec<Item> =
        serde_json::from_value(v).map_err(|e| PveError::Decode(e.to_string()))?;
    if items.iter().any(|i| i.vmid.is_none()) {
        return Err(PveError::Decode("guest list entry without vmid".into()));
    }
    Ok(items)
}

fn truthy(v: &Option<Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => s == "1",
        _ => false,
    }
}

fn parse_tags(t: &Option<String>) -> Vec<String> {
    t.as_deref()
        .unwrap_or("")
        .split([';', ',', ' '])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn fetch_config(
    client: &Arc<dyn PveApi>,
    node: &str,
    kind: GuestKind,
    vmid: &str,
) -> Result<Map<String, Value>, PveError> {
    let path = api_path(&["nodes", node, kind_segment(kind), vmid, "config"])?;
    match client.request(Method::Get, &path, &[]).await? {
        Value::Object(mut m) => {
            for k in SECRET_CONFIG_KEYS {
                m.remove(*k);
            }
            Ok(m)
        }
        _ => Err(PveError::Decode("config is not an object".into())),
    }
}

async fn fetch_status(
    client: &Arc<dyn PveApi>,
    node: &str,
    kind: GuestKind,
    vmid: &str,
) -> Result<Item, PveError> {
    let path = api_path(&["nodes", node, kind_segment(kind), vmid, "status", "current"])?;
    let v = client.request(Method::Get, &path, &[]).await?;
    serde_json::from_value(v).map_err(|e| PveError::Decode(e.to_string()))
}

/// Builds one guest from its list entry plus the two detail calls. A failed
/// detail call leaves the list data in place and records why; it never fails
/// the host.
async fn detail(
    client: Arc<dyn PveApi>,
    node: String,
    kind: GuestKind,
    item: Item,
) -> Result<Guest, PveError> {
    // `list` already rejected a missing vmid; this keeps the type honest.
    let vmid = item
        .vmid
        .ok_or_else(|| PveError::Decode("guest without vmid".into()))?;
    let vmid_s = vmid.to_string();
    let (cfg, st) = tokio::join!(
        fetch_config(&client, &node, kind, &vmid_s),
        fetch_status(&client, &node, kind, &vmid_s)
    );
    let mut errs = Vec::new();
    let config = match cfg {
        Ok(m) => Some(m),
        Err(e) => {
            errs.push(format!("config: {}", clean(e)));
            None
        }
    };
    // status/current is fresher than the list, so it wins where it has a value.
    let cur = match st {
        Ok(s) => s,
        Err(e) => {
            errs.push(format!("status: {}", clean(e)));
            Item::default()
        }
    };
    Ok(Guest {
        vmid,
        kind,
        node,
        name: cur.name.or(item.name),
        status: cur
            .status
            .or(item.status)
            .unwrap_or_else(|| "unknown".to_string()),
        cpus: cur.cpus.or(item.cpus),
        maxmem: cur.maxmem.or(item.maxmem),
        mem: cur.mem.or(item.mem),
        uptime: cur.uptime.or(item.uptime),
        template: truthy(&item.template) || truthy(&cur.template),
        tags: parse_tags(&cur.tags.or(item.tags)),
        stale: false,
        config,
        detail_error: if errs.is_empty() {
            None
        } else {
            Some(errs.join("; "))
        },
    })
}

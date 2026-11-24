//! The published shape of the inventory. These types are the API's JSON, so a
//! field is `Option` wherever PVE omits it (stopped guests have no `pid`,
//! offline nodes no `uptime`) rather than defaulted to a made-up zero.

use concord_core::GuestKind;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One coherent picture of the estate. Built whole by one cycle and swapped in
/// whole, so a reader never sees half of cycle N and half of N+1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EstateSnapshot {
    /// 1 for the first published cycle.
    pub cycle: u64,
    /// Unix seconds when the cycle finished.
    pub taken_at: u64,
    pub hosts: Vec<Host>,
    /// VMIDs present on more than one host. VMIDs are meant to be
    /// estate-unique; a clash is reported, never merged, because merging would
    /// hide which host a later action should touch.
    pub conflicts: Vec<Conflict>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    /// Configured but not yet polled.
    Pending,
    Ok,
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Host {
    /// The operator's name for the host (not necessarily its PVE node name).
    pub name: String,
    /// The PVE node name, once known.
    pub node: Option<String>,
    pub status: HostStatus,
    /// Why the host is unreachable; already free of credentials.
    pub error: Option<String>,
    pub pve_version: Option<String>,
    /// Unix seconds of the last fully successful poll.
    pub last_success: Option<u64>,
    pub guests: Vec<Guest>,
}

/// A host without its guests, for the host overview.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostSummary {
    pub name: String,
    pub node: Option<String>,
    pub status: HostStatus,
    pub error: Option<String>,
    pub pve_version: Option<String>,
    pub last_success: Option<u64>,
    pub guest_count: usize,
    pub stale_guests: usize,
}

impl Host {
    pub fn summary(&self) -> HostSummary {
        HostSummary {
            name: self.name.clone(),
            node: self.node.clone(),
            status: self.status,
            error: self.error.clone(),
            pve_version: self.pve_version.clone(),
            last_success: self.last_success,
            guest_count: self.guests.len(),
            stale_guests: self.guests.iter().filter(|g| g.stale).count(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Guest {
    pub vmid: u32,
    pub kind: GuestKind,
    /// The PVE node the guest was listed under (differs from the host's `node`
    /// only when the host is really a cluster).
    pub node: String,
    /// Absent in PVE's list for guests with no name set.
    pub name: Option<String>,
    /// PVE's status string verbatim (`running`, `stopped`, `paused`, ...): an
    /// unknown value must survive rather than fail the poll.
    pub status: String,
    pub cpus: Option<f64>,
    pub maxmem: Option<u64>,
    pub mem: Option<u64>,
    pub uptime: Option<u64>,
    pub template: bool,
    pub tags: Vec<String>,
    /// The data is from an earlier poll: the host or node did not answer.
    pub stale: bool,
    /// The keys of `/config` known to be safe to show. Omitted from list views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Map<String, Value>>,
    /// Names of the `/config` keys left out of `config`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_omitted: Vec<String>,
    /// Why the per-guest detail calls failed; the list data above is still
    /// the latest known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub vmid: u32,
    pub hosts: Vec<String>,
}

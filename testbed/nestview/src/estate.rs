//! What nestview may touch, and the only way to build a PVE path to it.
//!
//! The pool-scoped token can act on anything placed in the pool. nestview's
//! own container, CT 9004, is deliberately kept out of it, but
//! the pool's contents are not this binary's to guarantee, so the token's
//! ACLs are not the boundary: [`Vmid`] is. A `Vmid` exists only for the three
//! nested nodes, and every path below that names a guest takes one.

use std::fmt;

use concord_pve::{api_path, PveError};

/// The nested PVE nodes build.sh creates (`VMID_MIN`..`VMID_MAX` in
/// testbed/nested/lib.sh). Nothing else, not even 9004.
pub const ALLOWED_VMIDS: [u32; 3] = [9001, 9002, 9003];

/// Names from testbed/nested/lib.sh, used by the darken guards and the estate
/// view. Fixed rather than configurable: they describe the one estate this
/// binary is for.
pub const POOL: &str = "concord-nest";
pub const STORAGE: &str = "concord-nest";
pub const ZONE: &str = "cnestz";
pub const VNET: &str = "cnest";
pub const VM_TAG: &str = "concord-nest";

/// A VMID that passed the allowlist. No other constructor exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Vmid(u32);

#[derive(Debug, PartialEq, Eq)]
pub struct NotAllowed(pub String);

impl fmt::Display for NotAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VMID {} is not one of the nested nodes (allowed: 9001, 9002, 9003)",
            self.0
        )
    }
}

impl Vmid {
    pub fn new(id: u32) -> Result<Self, NotAllowed> {
        if ALLOWED_VMIDS.contains(&id) {
            Ok(Vmid(id))
        } else {
            Err(NotAllowed(id.to_string()))
        }
    }

    /// Parses a path segment. Anything that is not exactly an allowed decimal
    /// VMID is refused, including `09001` and `+9001`, so there is one spelling.
    pub fn parse(s: &str) -> Result<Self, NotAllowed> {
        let refused = || NotAllowed(s.chars().take(32).collect());
        if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refused());
        }
        let id: u32 = s.parse().map_err(|_| refused())?;
        Vmid::new(id).map_err(|_| refused())
    }

    pub fn all() -> [Vmid; 3] {
        ALLOWED_VMIDS.map(Vmid)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    /// `nest1`..`nest3`, as `vm_name` in lib.sh.
    pub fn expected_name(self) -> String {
        format!("nest{}", self.0 - ALLOWED_VMIDS[0] + 1)
    }
}

impl fmt::Display for Vmid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A PVE node name, validated once at config load the way the UPID parser
/// validates node fields: alphanumerics and inner hyphens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node(String);

impl Node {
    pub fn new(name: &str) -> Result<Self, String> {
        let ok = !name.is_empty()
            && name.len() <= 63
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if ok {
            Ok(Node(name.to_string()))
        } else {
            Err(format!("invalid node name {name:?}"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A snapshot name as PVE's `pve-snapshot-name` accepts it: `pve-configid`
/// (`[a-z][a-z0-9_-]+`, case-insensitive), at most 40 characters, and not
/// `current` or `pending`, which PVE reserves (pve-common JSONSchema.pm,
/// qemu-server API2/Qemu.pm). Checked here too so a bad name is a 400
/// from nestview, not something sent to the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapName(String);

impl SnapName {
    pub fn new(name: &str) -> Result<Self, String> {
        let b = name.as_bytes();
        let ok = (2..=40).contains(&b.len())
            && b[0].is_ascii_alphabetic()
            && b[1..]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'));
        let reserved = name.eq_ignore_ascii_case("current") || name.eq_ignore_ascii_case("pending");
        if ok && !reserved {
            Ok(SnapName(name.to_string()))
        } else {
            Err(
                "snapshot name must be 2-40 characters: a letter, then letters, digits, '_' or '-'; \
                 not 'current' or 'pending'"
                    .into(),
            )
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Every guest-scoped PVE path nestview can call. Each takes a [`Vmid`].
pub mod paths {
    use super::*;

    fn vm(node: &Node, vmid: Vmid, rest: &[&str]) -> Result<String, PveError> {
        let id = vmid.to_string();
        let mut segs = vec!["nodes", node.as_str(), "qemu", id.as_str()];
        segs.extend_from_slice(rest);
        api_path(&segs)
    }

    pub fn status_current(node: &Node, vmid: Vmid) -> Result<String, PveError> {
        vm(node, vmid, &["status", "current"])
    }

    pub fn config(node: &Node, vmid: Vmid) -> Result<String, PveError> {
        vm(node, vmid, &["config"])
    }

    pub fn snapshots(node: &Node, vmid: Vmid) -> Result<String, PveError> {
        vm(node, vmid, &["snapshot"])
    }

    pub fn rollback(node: &Node, vmid: Vmid, snap: &SnapName) -> Result<String, PveError> {
        vm(node, vmid, &["snapshot", snap.as_str(), "rollback"])
    }

    pub fn agent_interfaces(node: &Node, vmid: Vmid) -> Result<String, PveError> {
        vm(node, vmid, &["agent", "network-get-interfaces"])
    }

    /// `status/start`, `status/stop`, ... The verb comes from [`PowerVerb`],
    /// never from the request.
    pub fn power(node: &Node, vmid: Vmid, verb: PowerVerb) -> Result<String, PveError> {
        vm(node, vmid, &["status", verb.as_str()])
    }

    /// Node task list; the VMID goes in as the `vmid` filter parameter.
    pub fn node_tasks(node: &Node) -> Result<String, PveError> {
        api_path(&["nodes", node.as_str(), "tasks"])
    }

    pub fn node_sdn_zones(node: &Node) -> Result<String, PveError> {
        api_path(&["nodes", node.as_str(), "sdn", "zones"])
    }

    pub fn vnet() -> Result<String, PveError> {
        api_path(&["cluster", "sdn", "vnets", VNET])
    }

    pub fn storage_status(node: &Node) -> Result<String, PveError> {
        api_path(&["nodes", node.as_str(), "storage", STORAGE, "status"])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerVerb {
    Start,
    Stop,
    Reset,
    Suspend,
    Resume,
}

impl PowerVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            PowerVerb::Start => "start",
            PowerVerb::Stop => "stop",
            PowerVerb::Reset => "reset",
            PowerVerb::Suspend => "suspend",
            PowerVerb::Resume => "resume",
        }
    }
}

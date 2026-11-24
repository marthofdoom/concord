//! Shared vocabulary for Concord: the identities a guest, host, and job are
//! named by, and the errors every subsystem reports failure with.
//!
//! Nothing in this crate talks to the network. The PVE client, the Syncthing
//! client, and the orchestrator all sit above it so that the types a migration
//! decision is made from stay independent of how they were fetched.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Semantic version of the whole workspace, stamped from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A Proxmox node, addressed the way PVE itself addresses one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A guest, identified by the VMID that is unique across the estate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Vmid(pub u32);

impl fmt::Display for Vmid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which hypervisor a guest runs under. The two have different migration,
/// snapshot, and freeze semantics, so the distinction is load-bearing and is
/// never flattened into a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    /// A QEMU/KVM virtual machine.
    Qemu,
    /// An LXC container.
    Lxc,
}

/// Anything Concord refuses to do, and why.
///
/// Every variant is something an operator can act on. A migration that cannot
/// be performed says so rather than reporting success over a no-op — see the
/// "features ship complete" rule.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("guest {0} not found")]
    GuestNotFound(Vmid),

    #[error("node {0} is unreachable")]
    NodeUnreachable(NodeId),

    #[error("{operation} is not supported for this guest: {reason}")]
    NotSupported {
        operation: &'static str,
        reason: String,
    },

    #[error("proxmox api: {0}")]
    Api(String),
}

/// Result alias used throughout the workspace.
pub type Result<T> = std::result::Result<T, Error>;

/// What Concord can recover from, at a given estate size.
///
/// The two tiers need different things, and only the second one needs a second
/// machine. See `docs/ARCHITECTURE.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScope {
    /// No hosts: nothing to recover.
    None,
    /// One host. A guest that is down and should not be is started again. This
    /// needs no agreement with anyone — the host is right there and answering.
    GuestOnly,
    /// Two hosts or more. Everything above, plus restarting a dark host's
    /// guests elsewhere from their replicas.
    HostLoss,
}

/// What this estate can recover from.
pub fn recovery_scope(hosts: usize) -> RecoveryScope {
    match hosts {
        0 => RecoveryScope::None,
        1 => RecoveryScope::GuestOnly,
        _ => RecoveryScope::HostLoss,
    }
}

/// How long an isolated host may keep running its guests before stopping them
/// itself.
///
/// Safety on a host loss is a timing property, not a voting one: an isolated
/// host takes itself out rather than being out-voted, which is what lets a
/// two-host estate restore without a third opinion. The agent also pets
/// `/dev/watchdog` on this deadline, so a hung kernel is reset by hardware on
/// the same clock.
pub const FENCE_DEADLINE: Duration = Duration::from_secs(60);

/// Margin a survivor adds on top of the fence deadline before it restores.
const RESTORE_MARGIN: Duration = Duration::from_secs(15);

/// How long a survivor waits, after a host goes dark, before restoring its
/// guests.
///
/// Strictly greater than [`FENCE_DEADLINE`] — that inequality is the entire
/// safety argument. When a restore begins, the dark host is either dead or has
/// already stopped its own guests, and both are safe.
pub fn restore_delay(fence_deadline: Duration) -> Duration {
    fence_deadline + RESTORE_MARGIN
}

/// How a host can take a consistent snapshot of a guest disk and ship a delta
/// of it to another host.
///
/// This is *probed*, never configured: a host reports what it actually has, and
/// the leader plans against that. See `docs/ARCHITECTURE.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Replication {
    /// ZFS — native `snapshot` plus `send -i`. The cheapest path, and on an
    /// estate that is mostly bcachefs it is the special case, not the default.
    ZfsSendRecv,
    /// bcachefs — cheap consistent subvolume snapshots, but no `send`/`receive`
    /// in 1.38.x, so the transfer half must come from above the filesystem.
    BcachefsSnapshotOnly,
    /// LVM-thin — thin snapshots plus `thin_delta`.
    LvmThinDelta,
    /// A plain directory on ext4/XFS — qcow2 internal snapshots only.
    DirectoryOnly,
}

impl Replication {
    /// Whether the filesystem itself can ship an incremental.
    ///
    /// When it cannot, replication falls back to block-level incrementals
    /// driven by QEMU dirty bitmaps, which are filesystem-agnostic — the
    /// reason the default path does not depend on ZFS being present.
    pub fn has_native_delta(self) -> bool {
        matches!(self, Self::ZfsSendRecv | Self::LvmThinDelta)
    }
}

/// What the agent on a host reports about that host, beyond what the PVE API
/// exposes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostReport {
    pub node: NodeId,
    pub replication: Replication,
    /// Whether the kernel module backing guest storage resolves for the
    /// *running* kernel.
    ///
    /// Load-bearing: storage can depend on an out-of-tree (DKMS) module, as bcachefs
    /// does, so a kernel update whose DKMS build failed leaves a host that
    /// boots cleanly, answers the API, and has no storage. Such a host must be
    /// excluded as a target before it is chosen, not discovered mid-migration.
    pub storage_module_ok: bool,
}

impl HostReport {
    /// Whether this host may be chosen as a migration or restore target.
    ///
    /// "Available" has to mean storage works, not merely that the host answers.
    pub fn is_viable_target(&self) -> bool {
        self.storage_module_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_kind_serializes_as_pve_spells_it() {
        assert_eq!(serde_json::to_string(&GuestKind::Qemu).unwrap(), "\"qemu\"");
        assert_eq!(serde_json::to_string(&GuestKind::Lxc).unwrap(), "\"lxc\"");
    }

    #[test]
    fn unsupported_operations_name_themselves() {
        let err = Error::NotSupported {
            operation: "live-migrate",
            reason: "guest has a passthrough PCI device".into(),
        };
        assert!(err.to_string().contains("live-migrate"));
    }

    #[test]
    fn bcachefs_has_no_native_delta() {
        assert!(!Replication::BcachefsSnapshotOnly.has_native_delta());
        assert!(!Replication::DirectoryOnly.has_native_delta());
        assert!(Replication::ZfsSendRecv.has_native_delta());
    }

    #[test]
    fn one_host_still_recovers_its_own_guests() {
        assert_eq!(recovery_scope(0), RecoveryScope::None);
        assert_eq!(recovery_scope(1), RecoveryScope::GuestOnly);
        assert_eq!(recovery_scope(2), RecoveryScope::HostLoss);
        assert_eq!(recovery_scope(9), RecoveryScope::HostLoss);
    }

    #[test]
    fn a_survivor_never_restores_before_the_dark_host_has_fenced_itself() {
        // The entire safety argument for restoring without a third opinion.
        assert!(restore_delay(FENCE_DEADLINE) > FENCE_DEADLINE);

        for secs in [1, 30, 60, 600] {
            let fence = Duration::from_secs(secs);
            assert!(restore_delay(fence) > fence);
        }
    }

    #[test]
    fn a_host_with_a_broken_storage_module_is_not_a_target() {
        let mut report = HostReport {
            node: NodeId("pve1".into()),
            replication: Replication::BcachefsSnapshotOnly,
            storage_module_ok: true,
        };
        assert!(report.is_viable_target());

        // A failed DKMS build after a kernel update: the host is up, the API
        // answers, and it must not receive a guest.
        report.storage_module_ok = false;
        assert!(!report.is_viable_target());
    }
}

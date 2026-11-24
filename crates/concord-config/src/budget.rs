use serde::{Deserialize, Serialize};

/// Least the derived network cap may be; below it a backup would not finish.
const FLOOR_MB_PER_SEC: u64 = 30;
/// Assumed when the link speed is not given: the cautious direction to be
/// wrong in.
const DEFAULT_LINK_MBPS: u64 = 1000;
const DEFAULT_IO_WEIGHT: u16 = 10;

/// What backup and sync traffic may use: a hard cap on the network, and a
/// priority rather than a cap on the disk. See `docs/ARCHITECTURE.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budget {
    /// Narrowest link on the backup and sync path, in Mbit/s.
    pub link_mbps: u64,
    /// Sets the cap outright instead of deriving it from the link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mb_per_sec: Option<u64>,
    /// cgroup v2 `io.weight`, 1 to 10000; the kernel's default is 100.
    pub io_weight: u16,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            link_mbps: DEFAULT_LINK_MBPS,
            network_mb_per_sec: None,
            io_weight: DEFAULT_IO_WEIGHT,
        }
    }
}

impl Budget {
    /// The network cap in MB/s.
    ///
    /// The derived figures are ARCHITECTURE's, 50 at 1GbE and 300 at 10GbE, each
    /// scaled by link speed. Between them the 1GbE share stops at 300, so a
    /// faster link is never given less.
    pub fn network_cap_mb_per_sec(&self) -> u64 {
        self.network_mb_per_sec.unwrap_or_else(|| {
            let slow = (self.link_mbps / 20).min(300);
            let fast = if self.link_mbps >= 10_000 {
                self.link_mbps.saturating_mul(3) / 100
            } else {
                0
            };
            slow.max(fast).max(FLOOR_MB_PER_SEC)
        })
    }

    /// The offending field and what is wrong with it.
    pub(crate) fn check(&self) -> Result<(), (&'static str, &'static str)> {
        if self.link_mbps == 0 {
            return Err(("link_mbps", "must not be zero"));
        }
        if self.network_mb_per_sec == Some(0) {
            return Err(("network_mb_per_sec", "must not be zero"));
        }
        if !(1..=10_000).contains(&self.io_weight) {
            return Err(("io_weight", "must be 1 to 10000"));
        }
        Ok(())
    }
}
